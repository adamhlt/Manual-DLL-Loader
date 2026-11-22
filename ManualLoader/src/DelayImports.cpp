#include "DelayImports.hpp"

#include "Imports.hpp"
#include "Log.hpp"
#include "PeImage.hpp"

namespace MemoryLoader::Detail
{
	bool ResolveDelayImports(LPVOID lpImage) noexcept
	{
		if (lpImage == nullptr)
			return false;

		const IMAGE_DATA_DIRECTORY delayDirectory = GetDataDirectory(lpImage, IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT);
		if (delayDirectory.VirtualAddress == 0 || delayDirectory.Size == 0)
		{
			LogDebug("The image has no delay import directory.");
			return true;
		}

		const auto lpFirstDescriptor = reinterpret_cast<PDelayLoadDescriptor>(AsInteger(lpImage) + delayDirectory.VirtualAddress);
		for (auto lpDescriptor = lpFirstDescriptor; lpDescriptor->DllNameRva != 0; ++lpDescriptor)
		{
			// Only RVA-based descriptors (Visual Studio 2015 and later) are supported.
			if ((lpDescriptor->Attributes & 1) == 0)
			{
				LogWarning("Skipping a VA-based delay import descriptor.");
				continue;
			}

			const auto lpLibraryName = reinterpret_cast<const char*>(AsInteger(lpImage) + lpDescriptor->DllNameRva);
			const HMODULE hModule = LoadLibraryA(lpLibraryName);
			if (hModule == nullptr)
			{
				LogError("Unable to load the delay-loaded dependency \"%s\".", lpLibraryName);
				return false;
			}

			LogInfo("Resolving delay imports from \"%s\".", lpLibraryName);

			const DWORD_PTR dLookupRva = lpDescriptor->ImportNameTableRva != 0 ? lpDescriptor->ImportNameTableRva : lpDescriptor->ImportAddressTableRva;
			if (!ResolveImportTable(lpImage, hModule, lpLibraryName, dLookupRva, lpDescriptor->ImportAddressTableRva))
				return false;

			// Publish the module handle so the delay-load helper does not reload it.
			if (lpDescriptor->ModuleHandleRva != 0)
				*reinterpret_cast<HMODULE*>(AsInteger(lpImage) + lpDescriptor->ModuleHandleRva) = hModule;
		}

		return true;
	}
}
