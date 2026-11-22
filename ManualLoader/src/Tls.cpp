#include "Tls.hpp"

#include "Log.hpp"
#include "PeImage.hpp"

namespace MemoryLoader::Detail
{
	namespace
	{
		/** Returns the TLS directory of an image, or nullptr when there is none. */
		PIMAGE_TLS_DIRECTORY GetTlsDirectory(LPVOID lpImage) noexcept
		{
			const IMAGE_DATA_DIRECTORY directory = GetDataDirectory(lpImage, IMAGE_DIRECTORY_ENTRY_TLS);
			if (directory.VirtualAddress == 0)
				return nullptr;

			return reinterpret_cast<PIMAGE_TLS_DIRECTORY>(AsInteger(lpImage) + directory.VirtualAddress);
		}
	}

	void InitializeStaticTls(LPVOID lpImage) noexcept
	{
		if (lpImage == nullptr)
			return;

		const PIMAGE_TLS_DIRECTORY lpTlsDirectory = GetTlsDirectory(lpImage);
		if (lpTlsDirectory == nullptr || lpTlsDirectory->AddressOfIndex == 0)
			return;

		const SIZE_T dRawSize = static_cast<SIZE_T>(lpTlsDirectory->EndAddressOfRawData - lpTlsDirectory->StartAddressOfRawData);
		const SIZE_T dTotalSize = dRawSize + lpTlsDirectory->SizeOfZeroFill;
		if (dTotalSize == 0)
			return;

		const auto lpBlock = static_cast<LPVOID>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dTotalSize));
		if (lpBlock == nullptr)
		{
			LogWarning("Unable to allocate the static TLS block.");
			return;
		}

		if (dRawSize != 0)
			RtlCopyMemory(lpBlock, reinterpret_cast<LPCVOID>(lpTlsDirectory->StartAddressOfRawData), dRawSize);

		const DWORD dIndex = TlsAlloc();
		if (dIndex == TLS_OUT_OF_INDEXES)
		{
			LogWarning("Unable to allocate a TLS index.");
			HeapFree(GetProcessHeap(), 0, lpBlock);
			return;
		}

		*reinterpret_cast<DWORD_PTR*>(lpTlsDirectory->AddressOfIndex) = dIndex;
		TlsSetValue(dIndex, lpBlock);

		LogInfo("Static TLS initialized (index %lu, %zu bytes).", dIndex, dTotalSize);
	}

	void CleanupStaticTls(LPVOID lpImage) noexcept
	{
		if (lpImage == nullptr)
			return;

		const PIMAGE_TLS_DIRECTORY lpTlsDirectory = GetTlsDirectory(lpImage);
		if (lpTlsDirectory == nullptr || lpTlsDirectory->AddressOfIndex == 0)
			return;

		auto* lpIndex = reinterpret_cast<DWORD_PTR*>(lpTlsDirectory->AddressOfIndex);
		const DWORD dIndex = static_cast<DWORD>(*lpIndex);
		if (dIndex == 0 || dIndex == TLS_OUT_OF_INDEXES)
			return;

		if (const LPVOID lpBlock = TlsGetValue(dIndex); lpBlock != nullptr)
			HeapFree(GetProcessHeap(), 0, lpBlock);

		TlsFree(dIndex);
		*lpIndex = 0;

		LogInfo("Static TLS released.");
	}

	void RunTlsCallbacks(LPVOID lpImage, DWORD dwReason) noexcept
	{
		if (!HasTlsCallbacks(lpImage))
			return;

		const PIMAGE_TLS_DIRECTORY lpTlsDirectory = GetTlsDirectory(lpImage);
		if (lpTlsDirectory == nullptr || lpTlsDirectory->AddressOfCallBacks == 0)
			return;

		auto lpCallback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(lpTlsDirectory->AddressOfCallBacks);
		for (; *lpCallback != nullptr; ++lpCallback)
		{
			(*lpCallback)(lpImage, dwReason, nullptr);
		}

		LogInfo("TLS callbacks executed (reason %lu).", dwReason);
	}
}
