#include "Exports.hpp"

#include <cstdlib>
#include <cstring>

#include "Log.hpp"
#include "PeImage.hpp"

namespace MemoryLoader::Detail
{
	LPVOID ResolveExportAddress(LPVOID lpModule, DWORD dFunctionRva, const IMAGE_DATA_DIRECTORY& exportDirectory) noexcept
	{
		const DWORD_PTR dImageBase = AsInteger(lpModule);
		const DWORD_PTR dExportStart = exportDirectory.VirtualAddress;
		const DWORD_PTR dExportEnd = dExportStart + exportDirectory.Size;

		// An RVA inside the export directory is a forwarder string ("DLL.Function").
		if (dFunctionRva < dExportStart || dFunctionRva >= dExportEnd)
			return reinterpret_cast<LPVOID>(dImageBase + dFunctionRva);

		const auto lpForwarder = reinterpret_cast<const char*>(dImageBase + dFunctionRva);
		LogDebug("Forwarded export: %s", lpForwarder);

		const char* lpSeparator = std::strchr(lpForwarder, '.');
		if (lpSeparator == nullptr || lpSeparator == lpForwarder || *(lpSeparator + 1) == '\0')
		{
			LogWarning("Malformed forwarded export \"%s\".", lpForwarder);
			return nullptr;
		}

		char libraryName[MAX_PATH];
		const SIZE_T dNameLength = static_cast<SIZE_T>(lpSeparator - lpForwarder);
		if (dNameLength >= MAX_PATH)
		{
			LogWarning("Forwarded export module name is too long.");
			return nullptr;
		}

		std::memcpy(libraryName, lpForwarder, dNameLength);
		libraryName[dNameLength] = '\0';

		const char* lpTarget = lpSeparator + 1;

		HMODULE hTarget = GetModuleHandleA(libraryName);
		if (hTarget == nullptr)
			hTarget = LoadLibraryA(libraryName);
		if (hTarget == nullptr)
		{
			LogError("Unable to load the forwarded module \"%s\".", libraryName);
			return nullptr;
		}

		if (*lpTarget == '#')
		{
			const auto dOrdinal = static_cast<DWORD>(std::strtoul(lpTarget + 1, nullptr, 10));
			return reinterpret_cast<LPVOID>(GetProcAddress(hTarget, MAKEINTRESOURCEA(dOrdinal)));
		}

		return reinterpret_cast<LPVOID>(GetProcAddress(hTarget, lpTarget));
	}

	bool EnumerateExports(LPVOID lpModule, std::vector<Export>& exports)
	{
		exports.clear();

		if (lpModule == nullptr)
			return false;

		const IMAGE_DATA_DIRECTORY exportDirectory = GetDataDirectory(lpModule, IMAGE_DIRECTORY_ENTRY_EXPORT);
		if (exportDirectory.VirtualAddress == 0)
			return false;

		const auto lpExports = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(AsInteger(lpModule) + exportDirectory.VirtualAddress);
		const auto lpFunctions = reinterpret_cast<DWORD*>(AsInteger(lpModule) + lpExports->AddressOfFunctions);
		const auto lpNames = reinterpret_cast<DWORD*>(AsInteger(lpModule) + lpExports->AddressOfNames);
		const auto lpOrdinals = reinterpret_cast<WORD*>(AsInteger(lpModule) + lpExports->AddressOfNameOrdinals);

		for (DWORD i = 0; i < lpExports->NumberOfFunctions; ++i)
		{
			const DWORD dFunctionRva = lpFunctions[i];
			if (dFunctionRva == 0)
				continue;   // Unused slot.

			const char* lpName = nullptr;
			for (DWORD n = 0; n < lpExports->NumberOfNames; ++n)
			{
				if (lpOrdinals[n] == i)
				{
					lpName = reinterpret_cast<const char*>(AsInteger(lpModule) + lpNames[n]);
					break;
				}
			}

			Export entry{};
			entry.lpName = lpName;
			entry.dOrdinal = lpExports->Base + i;
			entry.lpAddress = ResolveExportAddress(lpModule, dFunctionRva, exportDirectory);
			exports.push_back(entry);
		}

		return true;
	}
}
