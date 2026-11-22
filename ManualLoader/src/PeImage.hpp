#ifndef MANUALLOADER_DETAIL_PEIMAGE_HPP
#define MANUALLOADER_DETAIL_PEIMAGE_HPP

#include "Common.hpp"

namespace MemoryLoader::Detail
{
	/** Pointers to the main structures of a PE image. */
	struct PeHeaders
	{
		PIMAGE_DOS_HEADER lpDosHeader = nullptr;
		PIMAGE_NT_HEADERS lpNtHeaders = nullptr;
		PIMAGE_SECTION_HEADER lpSectionHeaders = nullptr;
	};

	/** Returns the main PE structures of an image. */
	PeHeaders GetHeaders(LPVOID lpImage) noexcept;

	/** Checks that a raw PE image is well formed and fits in dImageSize bytes. */
	bool IsValidPe(LPVOID lpImage, SIZE_T dImageSize) noexcept;

	/** Checks that the PE image is a DLL. */
	bool IsDll(LPVOID lpImage) noexcept;

	/** Checks that the PE image matches the architecture of the current process. */
	bool IsCompatibleArchitecture(LPVOID lpImage) noexcept;

	/** Returns the size of the PE image once mapped. */
	DWORD_PTR GetImageSize(LPVOID lpImage) noexcept;

	/** Checks that the PE image declares TLS callbacks. */
	bool HasTlsCallbacks(LPVOID lpImage) noexcept;
}

#endif
