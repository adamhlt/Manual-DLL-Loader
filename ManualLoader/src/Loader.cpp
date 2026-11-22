#include "ManualLoader/Loader.hpp"

#include <cstring>

#include "Common.hpp"
#include "DelayImports.hpp"
#include "Exceptions.hpp"
#include "Exports.hpp"
#include "Imports.hpp"
#include "Log.hpp"
#include "PeImage.hpp"
#include "Protection.hpp"
#include "Relocations.hpp"
#include "Tls.hpp"

namespace MemoryLoader
{
	namespace
	{
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
		void MapImage(LPVOID lpMappedImage, LPVOID lpRawImage, const Detail::PeHeaders& rawHeaders) noexcept
		{
			RtlCopyMemory(lpMappedImage, lpRawImage, rawHeaders.lpNtHeaders->OptionalHeader.SizeOfHeaders);

			const auto lpMappedNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(Detail::AsInteger(lpMappedImage) + rawHeaders.lpDosHeader->e_lfanew);
			lpMappedNtHeaders->OptionalHeader.ImageBase = Detail::AsInteger(lpMappedImage);

			for (WORD i = 0; i < rawHeaders.lpNtHeaders->FileHeader.NumberOfSections; ++i)
			{
				const PIMAGE_SECTION_HEADER lpSection = &rawHeaders.lpSectionHeaders[i];
				if (lpSection->SizeOfRawData == 0)
					continue;

				RtlCopyMemory(
					reinterpret_cast<LPVOID>(Detail::AsInteger(lpMappedImage) + lpSection->VirtualAddress),
					reinterpret_cast<LPCVOID>(Detail::AsInteger(lpRawImage) + lpSection->PointerToRawData),
					lpSection->SizeOfRawData);

				LogDebug("Section %s mapped.", reinterpret_cast<const char*>(lpSection->Name));
			}
		}

		/** Maps and initializes a raw PE image. Returns the module base or nullptr. */
		LPVOID MapAndInitialize(LPVOID lpRawImage, SIZE_T dRawSize, Status* pStatus)
		{
			const auto fail = [pStatus](Status status) noexcept -> LPVOID
			{
				if (pStatus != nullptr)
					*pStatus = status;
				return nullptr;
			};

			if (lpRawImage == nullptr || dRawSize == 0)
				return fail(Status::InvalidArgument);

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

			if (!Detail::ResolveDelayImports(mappedImage.Get()))
				return fail(Status::DelayImportResolutionFailed);
			LogInfo("Delay imports resolved.");

			Detail::InitializeStaticTls(mappedImage.Get());
			Detail::RunTlsCallbacks(mappedImage.Get(), DLL_PROCESS_ATTACH);

			if (!Detail::RegisterExceptionTable(mappedImage.Get()))
				return fail(Status::ExceptionTableFailed);

			if (!Detail::ApplySectionProtections(mappedImage.Get()))
				return fail(Status::ProtectionFailed);

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
	}

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

		LogInfo("PE file read at 0x%p (%zu bytes).", fileContent.Data(), fileContent.Size());
		return MapAndInitialize(fileContent.Data(), fileContent.Size(), pStatus);
	}

	LPVOID LoadDLLFromMemory(LPCVOID lpImage, SIZE_T dImageSize)
	{
		return LoadDLLFromMemory(lpImage, dImageSize, nullptr);
	}

	LPVOID LoadDLLFromMemory(LPCVOID lpImage, SIZE_T dImageSize, Status* pStatus)
	{
		LogInfo("DLL LOADER (from memory)");
		return MapAndInitialize(const_cast<LPVOID>(lpImage), dImageSize, pStatus);
	}

	LPVOID GetFunctionAddress(LPVOID lpModule, const char* lpFunctionName)
	{
		if (lpModule == nullptr || lpFunctionName == nullptr)
			return nullptr;

		const IMAGE_DATA_DIRECTORY exportDirectory = Detail::GetDataDirectory(lpModule, IMAGE_DIRECTORY_ENTRY_EXPORT);
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
				return Detail::ResolveExportAddress(lpModule, lpFunctions[lpOrdinals[i]], exportDirectory);
		}

		return nullptr;
	}

	LPVOID GetFunctionAddressByOrdinal(LPVOID lpModule, DWORD_PTR dOrdinal)
	{
		if (lpModule == nullptr)
			return nullptr;

		const IMAGE_DATA_DIRECTORY exportDirectory = Detail::GetDataDirectory(lpModule, IMAGE_DIRECTORY_ENTRY_EXPORT);
		if (exportDirectory.VirtualAddress == 0)
			return nullptr;

		const auto lpExports = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(Detail::AsInteger(lpModule) + exportDirectory.VirtualAddress);
		if (dOrdinal < lpExports->Base)
			return nullptr;

		const DWORD_PTR dIndex = dOrdinal - lpExports->Base;
		if (dIndex >= lpExports->NumberOfFunctions)
			return nullptr;

		const auto lpFunctions = reinterpret_cast<DWORD*>(Detail::AsInteger(lpModule) + lpExports->AddressOfFunctions);
		return Detail::ResolveExportAddress(lpModule, lpFunctions[dIndex], exportDirectory);
	}

	bool GetExports(LPVOID lpModule, std::vector<Export>& exports)
	{
		return Detail::EnumerateExports(lpModule, exports);
	}

	std::vector<Export> GetExports(LPVOID lpModule)
	{
		std::vector<Export> exports;
		Detail::EnumerateExports(lpModule, exports);
		return exports;
	}

	void RunTlsCallbacks(LPVOID lpModule, DWORD dwReason)
	{
		Detail::RunTlsCallbacks(lpModule, dwReason);
	}

	BOOL FreeDLL(LPVOID lpModule)
	{
		if (lpModule == nullptr)
			return FALSE;

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

		Detail::RunTlsCallbacks(lpModule, DLL_PROCESS_DETACH);
		Detail::CleanupStaticTls(lpModule);
		Detail::UnregisterExceptionTable(lpModule);

		if (!VirtualFree(lpModule, 0, MEM_RELEASE))
		{
			LogError("Unable to free the DLL memory.");
			return FALSE;
		}

		LogInfo("DLL unloaded successfully.");
		return TRUE;
	}

	Module::Module(LPVOID lpBase) noexcept : m_lpBase(lpBase)
	{
	}

	Module::~Module()
	{
		Reset();
	}

	Module::Module(Module&& other) noexcept : m_lpBase(other.m_lpBase)
	{
		other.m_lpBase = nullptr;
	}

	Module& Module::operator=(Module&& other) noexcept
	{
		if (this != &other)
		{
			Reset();
			m_lpBase = other.m_lpBase;
			other.m_lpBase = nullptr;
		}
		return *this;
	}

	Module Module::FromFile(const char* lpDLLPath, Status* pStatus)
	{
		return Module(LoadDLL(lpDLLPath, pStatus));
	}

	Module Module::FromMemory(LPCVOID lpImage, SIZE_T dImageSize, Status* pStatus)
	{
		return Module(LoadDLLFromMemory(lpImage, dImageSize, pStatus));
	}

	bool Module::IsValid() const noexcept
	{
		return m_lpBase != nullptr;
	}

	LPVOID Module::Get() const noexcept
	{
		return m_lpBase;
	}

	Module::operator bool() const noexcept
	{
		return m_lpBase != nullptr;
	}

	LPVOID Module::GetFunction(const char* lpFunctionName) const
	{
		return GetFunctionAddress(m_lpBase, lpFunctionName);
	}

	LPVOID Module::GetFunctionByOrdinal(DWORD_PTR dOrdinal) const
	{
		return GetFunctionAddressByOrdinal(m_lpBase, dOrdinal);
	}

	std::vector<Export> Module::GetExports() const
	{
		return MemoryLoader::GetExports(m_lpBase);
	}

	LPVOID Module::Release() noexcept
	{
		LPVOID lpBase = m_lpBase;
		m_lpBase = nullptr;
		return lpBase;
	}

	void Module::Reset() noexcept
	{
		if (m_lpBase != nullptr)
		{
			FreeDLL(m_lpBase);
			m_lpBase = nullptr;
		}
	}
}
