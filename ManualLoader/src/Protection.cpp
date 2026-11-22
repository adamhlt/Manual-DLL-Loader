#include "Protection.hpp"

#include "Log.hpp"
#include "PeImage.hpp"

namespace MemoryLoader::Detail
{
	namespace
	{
		DWORD ProtectionForSection(DWORD dCharacteristics) noexcept
		{
			if ((dCharacteristics & IMAGE_SCN_MEM_EXECUTE) != 0)
				return (dCharacteristics & IMAGE_SCN_MEM_WRITE) != 0 ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;

			if ((dCharacteristics & IMAGE_SCN_MEM_WRITE) != 0)
				return PAGE_READWRITE;

			if ((dCharacteristics & IMAGE_SCN_MEM_READ) != 0)
				return PAGE_READONLY;

			return PAGE_NOACCESS;
		}
	}

	bool ApplySectionProtections(LPVOID lpImage) noexcept
	{
		if (lpImage == nullptr)
			return false;

		const PeHeaders headers = GetHeaders(lpImage);

		const DWORD dHeadersSize = headers.lpNtHeaders->OptionalHeader.SizeOfHeaders;
		if (dHeadersSize != 0)
		{
			DWORD dOldProtection = 0;
			if (!VirtualProtect(lpImage, dHeadersSize, PAGE_READONLY, &dOldProtection))
			{
				LogError("Unable to protect the PE headers.");
				return false;
			}
		}

		for (WORD i = 0; i < headers.lpNtHeaders->FileHeader.NumberOfSections; ++i)
		{
			const PIMAGE_SECTION_HEADER lpSection = &headers.lpSectionHeaders[i];
			const SIZE_T dSize = lpSection->Misc.VirtualSize != 0 ? lpSection->Misc.VirtualSize : lpSection->SizeOfRawData;
			if (dSize == 0)
				continue;

			const DWORD dProtection = ProtectionForSection(lpSection->Characteristics);

			DWORD dOldProtection = 0;
			if (!VirtualProtect(reinterpret_cast<LPVOID>(AsInteger(lpImage) + lpSection->VirtualAddress), dSize, dProtection, &dOldProtection))
			{
				LogError("Unable to protect the section %s.", reinterpret_cast<const char*>(lpSection->Name));
				return false;
			}

			LogDebug("Section %s protected (0x%lx).", reinterpret_cast<const char*>(lpSection->Name), dProtection);
		}

		LogInfo("Section protections applied.");
		return true;
	}
}
