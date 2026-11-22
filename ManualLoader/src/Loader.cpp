#include "ManualLoader/Loader.hpp"

#include <cstring>

#include "Common.hpp"
#include "Imports.hpp"
#include "Log.hpp"
#include "PeImage.hpp"
#include "Relocations.hpp"
#include "Tls.hpp"

namespace
{
	using namespace MemoryLoader;
	using namespace MemoryLoader::Detail;

	/** RAII wrapper around a buffer allocated with HeapAlloc. */
	class HeapBuffer
	{
	public:
		HeapBuffer() = default;
		~HeapBuffer() { Reset(); }

		HeapBuffer(const HeapBuffer&) = delete;
		HeapBuffer& operator=(const HeapBuffer&) = delete;

		LPVOID Data() const noexcept { return m_lpData; }
		SIZE_T Size() const noexcept { return m_dSize; }

		/** Reads the whole content of a file into the buffer. */
		bool ReadFromFile(const char* lpFilePath) noexcept
		{
			Reset();

			const HANDLE hFile = CreateFileA(lpFilePath, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
			if (hFile == INVALID_HANDLE_VALUE)
			{
				LogError("Unable to open \"%s\".", lpFilePath);
				return false;
			}

			LARGE_INTEGER fileSize{};
			if (!GetFileSizeEx(hFile, &fileSize) || fileSize.QuadPart <= 0 || fileSize.HighPart != 0)
			{
				LogError("Unable to determine the size of \"%s\".", lpFilePath);
				CloseHandle(hFile);
				return false;
			}

			m_dSize = static_cast<SIZE_T>(fileSize.LowPart);
			m_lpData = HeapAlloc(GetProcessHeap(), 0, m_dSize);
			if (m_lpData == nullptr)
			{
				LogError("Unable to allocate memory for the PE file content.");
				CloseHandle(hFile);
				return false;
			}

			DWORD dRead = 0;
			const BOOL bRead = ReadFile(hFile, m_lpData, static_cast<DWORD>(m_dSize), &dRead, nullptr);
			CloseHandle(hFile);

			if (!bRead || dRead != m_dSize)
			{
				LogError("Unable to read \"%s\".", lpFilePath);
				Reset();
				return false;
			}

			return true;
		}

	private:
		void Reset() noexcept
		{
			if (m_lpData != nullptr)
			{
				HeapFree(GetProcessHeap(), 0, m_lpData);
				m_lpData = nullptr;
			}
			m_dSize = 0;
		}

		LPVOID m_lpData = nullptr;
		SIZE_T m_dSize = 0;
	};

	/** RAII wrapper around an image allocated with VirtualAlloc. */
	class MappedImage
	{
	public:
		MappedImage() = default;
		~MappedImage()
		{
			if (m_lpBase != nullptr)
				VirtualFree(m_lpBase, 0, MEM_RELEASE);
		}

		MappedImage(const MappedImage&) = delete;
		MappedImage& operator=(const MappedImage&) = delete;

		bool Allocate(SIZE_T dSize) noexcept
		{
			m_lpBase = VirtualAlloc(nullptr, dSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			return m_lpBase != nullptr;
		}

		LPVOID Get() const noexcept { return m_lpBase; }

		/** Relinquishes ownership; the caller becomes responsible for freeing the image. */
		LPVOID Release() noexcept
		{
			LPVOID lpBase = m_lpBase;
			m_lpBase = nullptr;
			return lpBase;
		}

	private:
		LPVOID m_lpBase = nullptr;
	};

	/** Copies the headers and the sections of a raw PE image into a mapped image. */
	void MapImage(LPVOID lpMappedImage, LPVOID lpRawImage, const PeHeaders& rawHeaders) noexcept
	{
		RtlCopyMemory(lpMappedImage, lpRawImage, rawHeaders.lpNtHeaders->OptionalHeader.SizeOfHeaders);

		const auto lpMappedNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(AsInteger(lpMappedImage) + rawHeaders.lpDosHeader->e_lfanew);
		lpMappedNtHeaders->OptionalHeader.ImageBase = AsInteger(lpMappedImage);

		for (WORD i = 0; i < rawHeaders.lpNtHeaders->FileHeader.NumberOfSections; ++i)
		{
			const PIMAGE_SECTION_HEADER lpSection = &rawHeaders.lpSectionHeaders[i];
			if (lpSection->SizeOfRawData == 0)
				continue;

			RtlCopyMemory(
				reinterpret_cast<LPVOID>(AsInteger(lpMappedImage) + lpSection->VirtualAddress),
				reinterpret_cast<LPCVOID>(AsInteger(lpRawImage) + lpSection->PointerToRawData),
				lpSection->SizeOfRawData);

			LogDebug("Section %s mapped.", reinterpret_cast<const char*>(lpSection->Name));
		}
	}
}

namespace MemoryLoader
{
	LPVOID LoadDLL(const char* lpDLLPath)
	{
		return LoadDLL(lpDLLPath, nullptr);
	}

	LPVOID LoadDLL(const char* lpDLLPath, Status* pStatus)
	{
		const auto fail = [pStatus](Status status) noexcept -> LPVOID
		{
			if (pStatus != nullptr)
				*pStatus = status;
			return nullptr;
		};

		LogInfo("DLL LOADER");

		if (lpDLLPath == nullptr)
			return fail(Status::InvalidArgument);

		HeapBuffer fileContent;
		if (!fileContent.ReadFromFile(lpDLLPath))
			return fail(Status::FileNotFound);

		LPVOID lpRawImage = fileContent.Data();
		const SIZE_T dRawSize = fileContent.Size();
		LogInfo("PE file read at 0x%p (%zu bytes).", lpRawImage, dRawSize);

		if (!Detail::IsValidPe(lpRawImage, dRawSize))
			return fail(Status::InvalidPe);
		LogInfo("The PE image is valid.");

		if (!Detail::IsDll(lpRawImage))
			return fail(Status::NotADll);
		LogInfo("The PE image corresponds to a DLL.");

		if (!Detail::IsCompatibleArchitecture(lpRawImage))
			return fail(Status::ArchitectureMismatch);
		LogInfo("The architectures are compatible.");

		const Detail::PeHeaders rawHeaders = Detail::GetHeaders(lpRawImage);
		const DWORD_PTR dImageSize = rawHeaders.lpNtHeaders->OptionalHeader.SizeOfImage;

		MappedImage mappedImage;
		if (!mappedImage.Allocate(dImageSize))
			return fail(Status::AllocationFailed);
		LogInfo("DLL memory allocated at 0x%p (0x%zx bytes).", mappedImage.Get(), static_cast<size_t>(dImageSize));

		const DWORD_PTR dDelta = Detail::AsInteger(mappedImage.Get()) - static_cast<DWORD_PTR>(rawHeaders.lpNtHeaders->OptionalHeader.ImageBase);

		MapImage(mappedImage.Get(), lpRawImage, rawHeaders);

		if (!Detail::ApplyRelocations(mappedImage.Get(), dDelta))
			return fail(Status::RelocationFailed);
		LogInfo("Relocations applied.");

		if (!Detail::ResolveImports(mappedImage.Get()))
			return fail(Status::ImportResolutionFailed);
		LogInfo("Imports resolved.");

		Detail::RunTlsCallbacks(mappedImage.Get(), DLL_PROCESS_ATTACH);

		const auto lpMappedNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(Detail::AsInteger(mappedImage.Get()) + rawHeaders.lpDosHeader->e_lfanew);
		const DWORD_PTR dEntryPoint = lpMappedNtHeaders->OptionalHeader.AddressOfEntryPoint;
		if (dEntryPoint != 0)
		{
			const auto DllMain = reinterpret_cast<Detail::DllMainFn>(Detail::AsInteger(mappedImage.Get()) + dEntryPoint);
			if (!DllMain(reinterpret_cast<HINSTANCE>(mappedImage.Get()), DLL_PROCESS_ATTACH, nullptr))
				return fail(Status::EntryPointFailed);
			LogInfo("DllMain called (DLL_PROCESS_ATTACH).");
		}

		LogInfo("DLL loaded successfully.");

		if (pStatus != nullptr)
			*pStatus = Status::Success;
		return mappedImage.Release();
	}

	LPVOID GetFunctionAddress(LPVOID lpModule, const char* lpFunctionName)
	{
		if (lpModule == nullptr || lpFunctionName == nullptr)
			return nullptr;

		const Detail::PeHeaders headers = Detail::GetHeaders(lpModule);
		const IMAGE_DATA_DIRECTORY exportDirectory = headers.lpNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
		if (exportDirectory.VirtualAddress == 0)
			return nullptr;

		const auto lpExports = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(Detail::AsInteger(lpModule) + exportDirectory.VirtualAddress);
		const auto lpNames = reinterpret_cast<DWORD*>(Detail::AsInteger(lpModule) + lpExports->AddressOfNames);
		const auto lpOrdinals = reinterpret_cast<WORD*>(Detail::AsInteger(lpModule) + lpExports->AddressOfNameOrdinals);
		const auto lpFunctions = reinterpret_cast<DWORD*>(Detail::AsInteger(lpModule) + lpExports->AddressOfFunctions);

		for (DWORD i = 0; i < lpExports->NumberOfNames; ++i)
		{
			const auto lpCurrentName = reinterpret_cast<const char*>(Detail::AsInteger(lpModule) + lpNames[i]);
			if (std::strcmp(lpCurrentName, lpFunctionName) == 0)
				return reinterpret_cast<LPVOID>(Detail::AsInteger(lpModule) + lpFunctions[lpOrdinals[i]]);
		}

		return nullptr;
	}

	LPVOID GetFunctionAddressByOrdinal(LPVOID lpModule, DWORD_PTR dOrdinal)
	{
		if (lpModule == nullptr)
			return nullptr;

		const Detail::PeHeaders headers = Detail::GetHeaders(lpModule);
		const IMAGE_DATA_DIRECTORY exportDirectory = headers.lpNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
		if (exportDirectory.VirtualAddress == 0)
			return nullptr;

		const auto lpExports = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(Detail::AsInteger(lpModule) + exportDirectory.VirtualAddress);
		if (dOrdinal < lpExports->Base)
			return nullptr;

		const DWORD_PTR dIndex = dOrdinal - lpExports->Base;
		if (dIndex >= lpExports->NumberOfFunctions)
			return nullptr;

		const auto lpFunctions = reinterpret_cast<DWORD*>(Detail::AsInteger(lpModule) + lpExports->AddressOfFunctions);
		return reinterpret_cast<LPVOID>(Detail::AsInteger(lpModule) + lpFunctions[dIndex]);
	}

	BOOL FreeDLL(LPVOID lpModule)
	{
		if (lpModule == nullptr)
			return FALSE;

		Detail::RunTlsCallbacks(lpModule, DLL_PROCESS_DETACH);

		const Detail::PeHeaders headers = Detail::GetHeaders(lpModule);
		const DWORD_PTR dEntryPoint = headers.lpNtHeaders->OptionalHeader.AddressOfEntryPoint;
		if (dEntryPoint != 0)
		{
			const auto DllMain = reinterpret_cast<Detail::DllMainFn>(Detail::AsInteger(lpModule) + dEntryPoint);
			if (!DllMain(reinterpret_cast<HINSTANCE>(lpModule), DLL_PROCESS_DETACH, nullptr))
			{
				LogError("DllMain failed (DLL_PROCESS_DETACH).");
				return FALSE;
			}
			LogInfo("DllMain called (DLL_PROCESS_DETACH).");
		}

		if (!VirtualFree(lpModule, 0, MEM_RELEASE))
		{
			LogError("Unable to free the DLL memory.");
			return FALSE;
		}

		LogInfo("DLL unloaded successfully.");
		return TRUE;
	}
}
