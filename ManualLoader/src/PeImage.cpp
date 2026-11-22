#include "PeImage.hpp"

namespace MemoryLoader::Detail
{
	PeHeaders GetHeaders(LPVOID lpImage) noexcept
	{
		PeHeaders headers;
		if (lpImage == nullptr)
			return headers;

		headers.lpDosHeader = static_cast<PIMAGE_DOS_HEADER>(lpImage);
		headers.lpNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(AsInteger(lpImage) + headers.lpDosHeader->e_lfanew);
		headers.lpSectionHeaders = reinterpret_cast<PIMAGE_SECTION_HEADER>(
			AsInteger(headers.lpNtHeaders) + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + headers.lpNtHeaders->FileHeader.SizeOfOptionalHeader);

		return headers;
	}

	bool IsValidPe(LPVOID lpImage, SIZE_T dImageSize) noexcept
	{
		if (lpImage == nullptr || dImageSize < sizeof(IMAGE_DOS_HEADER))
			return false;

		const auto lpDosHeader = static_cast<PIMAGE_DOS_HEADER>(lpImage);
		if (lpDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
			return false;

		const DWORD_PTR dNtOffset = static_cast<DWORD_PTR>(lpDosHeader->e_lfanew);
		if (dNtOffset + sizeof(IMAGE_NT_HEADERS) > dImageSize)
			return false;

		const auto lpNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(AsInteger(lpImage) + dNtOffset);
		return lpNtHeaders->Signature == IMAGE_NT_SIGNATURE;
	}

	bool IsDll(LPVOID lpImage) noexcept
	{
		if (lpImage == nullptr)
			return false;

		const PeHeaders headers = GetHeaders(lpImage);
		return (headers.lpNtHeaders->FileHeader.Characteristics & IMAGE_FILE_DLL) != 0;
	}

	bool IsCompatibleArchitecture(LPVOID lpImage) noexcept
	{
		if (lpImage == nullptr)
			return false;

		const PeHeaders headers = GetHeaders(lpImage);
		return headers.lpNtHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR_MAGIC;
	}

	DWORD_PTR GetImageSize(LPVOID lpImage) noexcept
	{
		if (lpImage == nullptr)
			return 0;

		const PeHeaders headers = GetHeaders(lpImage);
		return headers.lpNtHeaders->OptionalHeader.SizeOfImage;
	}

	bool HasTlsCallbacks(LPVOID lpImage) noexcept
	{
		if (lpImage == nullptr)
			return false;

		const PeHeaders headers = GetHeaders(lpImage);
		return headers.lpNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress != 0;
	}
}
