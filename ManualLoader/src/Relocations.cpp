#include "Relocations.hpp"

#include "Log.hpp"
#include "PeImage.hpp"

namespace MemoryLoader::Detail
{
	bool ApplyRelocations(LPVOID lpImage, DWORD_PTR dDelta) noexcept
	{
		if (lpImage == nullptr)
			return false;

		const PeHeaders headers = GetHeaders(lpImage);
		const IMAGE_DATA_DIRECTORY relocDirectory = headers.lpNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
		if (relocDirectory.VirtualAddress == 0 || relocDirectory.Size == 0)
		{
			LogDebug("The image has no relocation directory.");
			return true;
		}

		const DWORD_PTR dRelocStart = AsInteger(lpImage) + relocDirectory.VirtualAddress;
		DWORD_PTR dConsumed = 0;
		while (dConsumed < relocDirectory.Size)
		{
			const auto lpBlock = reinterpret_cast<PIMAGE_BASE_RELOCATION>(dRelocStart + dConsumed);
			if (lpBlock->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION))
			{
				LogError("Invalid relocation block.");
				return false;
			}

			dConsumed += sizeof(IMAGE_BASE_RELOCATION);

			const DWORD_PTR dEntryCount = (lpBlock->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(RelocationEntry);
			for (DWORD_PTR i = 0; i < dEntryCount; ++i)
			{
				const auto lpEntry = reinterpret_cast<RelocationEntry*>(dRelocStart + dConsumed);
				dConsumed += sizeof(RelocationEntry);

				const DWORD_PTR dPatchAddress = AsInteger(lpImage) + lpBlock->VirtualAddress + lpEntry->Offset;

				switch (lpEntry->Type)
				{
				case IMAGE_REL_BASED_ABSOLUTE:
					// Padding entry, nothing to patch.
					break;

				case IMAGE_REL_BASED_HIGHLOW:
				{
					const auto lpTarget = reinterpret_cast<DWORD*>(dPatchAddress);
					*lpTarget = static_cast<DWORD>(*lpTarget + dDelta);
					break;
				}

				case IMAGE_REL_BASED_HIGH:
				{
					const auto lpTarget = reinterpret_cast<WORD*>(dPatchAddress);
					*lpTarget = static_cast<WORD>(*lpTarget + HIWORD(dDelta));
					break;
				}

				case IMAGE_REL_BASED_LOW:
				{
					const auto lpTarget = reinterpret_cast<WORD*>(dPatchAddress);
					*lpTarget = static_cast<WORD>(*lpTarget + LOWORD(dDelta));
					break;
				}

#ifdef _WIN64
				case IMAGE_REL_BASED_DIR64:
				{
					const auto lpTarget = reinterpret_cast<DWORD_PTR*>(dPatchAddress);
					*lpTarget += dDelta;
					break;
				}
#endif

				default:
					LogError("Unsupported relocation type %u.", lpEntry->Type);
					return false;
				}
			}
		}

		return true;
	}
}
