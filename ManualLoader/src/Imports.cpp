#include "Imports.hpp"

#include "Log.hpp"
#include "PeImage.hpp"

namespace MemoryLoader::Detail
{
	bool ResolveImportTable(LPVOID lpImage, HMODULE hModule, const char* lpLibraryName, DWORD_PTR dLookupRva, DWORD_PTR dIatRva) noexcept
	{
		auto lpLookup = reinterpret_cast<PIMAGE_THUNK_DATA>(AsInteger(lpImage) + dLookupRva);
		auto lpIat = reinterpret_cast<PIMAGE_THUNK_DATA>(AsInteger(lpImage) + dIatRva);

		for (; lpLookup->u1.AddressOfData != 0; ++lpLookup, ++lpIat)
		{
			if (IMAGE_SNAP_BY_ORDINAL(lpLookup->u1.Ordinal))
			{
				const WORD dOrdinal = static_cast<WORD>(IMAGE_ORDINAL(lpLookup->u1.Ordinal));
				lpIat->u1.Function = reinterpret_cast<DWORD_PTR>(GetProcAddress(hModule, MAKEINTRESOURCEA(dOrdinal)));
				LogDebug("  Ordinal %u", dOrdinal);
			}
			else
			{
				const auto lpImport = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(AsInteger(lpImage) + lpLookup->u1.AddressOfData);
				lpIat->u1.Function = reinterpret_cast<DWORD_PTR>(GetProcAddress(hModule, reinterpret_cast<LPCSTR>(lpImport->Name)));
				LogDebug("  %s", lpImport->Name);
			}

			if (lpIat->u1.Function == 0)
			{
				LogError("Unable to resolve an import from \"%s\".", lpLibraryName);
				return false;
			}
		}

		return true;
	}

	bool ResolveImports(LPVOID lpImage) noexcept
	{
		if (lpImage == nullptr)
			return false;

		const IMAGE_DATA_DIRECTORY importDirectory = GetDataDirectory(lpImage, IMAGE_DIRECTORY_ENTRY_IMPORT);
		if (importDirectory.VirtualAddress == 0 || importDirectory.Size == 0)
		{
			LogDebug("The image has no import directory.");
			return true;
		}

		const auto lpFirstDescriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(AsInteger(lpImage) + importDirectory.VirtualAddress);
		for (auto lpDescriptor = lpFirstDescriptor; lpDescriptor->Name != 0; ++lpDescriptor)
		{
			const auto lpLibraryName = reinterpret_cast<const char*>(AsInteger(lpImage) + lpDescriptor->Name);
			const HMODULE hModule = LoadLibraryA(lpLibraryName);
			if (hModule == nullptr)
			{
				LogError("Unable to load the dependency \"%s\".", lpLibraryName);
				return false;
			}

			LogInfo("Resolving imports from \"%s\".", lpLibraryName);

			// Prefer the original thunk (names) and always write into the IAT.
			const DWORD_PTR dLookupRva = lpDescriptor->OriginalFirstThunk != 0 ? lpDescriptor->OriginalFirstThunk : lpDescriptor->FirstThunk;
			if (!ResolveImportTable(lpImage, hModule, lpLibraryName, dLookupRva, lpDescriptor->FirstThunk))
				return false;
		}

		return true;
	}
}
