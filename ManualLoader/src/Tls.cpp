#include "Tls.hpp"

#include "Log.hpp"
#include "PeImage.hpp"

namespace MemoryLoader::Detail
{
	void RunTlsCallbacks(LPVOID lpImage, DWORD dwReason) noexcept
	{
		if (!HasTlsCallbacks(lpImage))
			return;

		const PeHeaders headers = GetHeaders(lpImage);
		const DWORD_PTR dTlsRva = headers.lpNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
		if (dTlsRva == 0)
			return;

		const auto lpTlsDirectory = reinterpret_cast<PIMAGE_TLS_DIRECTORY>(AsInteger(lpImage) + dTlsRva);
		if (lpTlsDirectory->AddressOfCallBacks == 0)
			return;

		auto lpCallback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(lpTlsDirectory->AddressOfCallBacks);
		for (; *lpCallback != nullptr; ++lpCallback)
		{
			(*lpCallback)(lpImage, dwReason, nullptr);
		}

		LogInfo("TLS callbacks executed (reason %lu).", dwReason);
	}
}
