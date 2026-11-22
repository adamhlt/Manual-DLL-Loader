#ifndef MANUALLOADER_DETAIL_IMPORTS_HPP
#define MANUALLOADER_DETAIL_IMPORTS_HPP

#include "Common.hpp"

namespace MemoryLoader::Detail
{
	/**
	 *	Resolves the import address table of a mapped PE image.
	 *	\param lpImage : base address of the mapped image.
	 *	\return : true if all imports were resolved, false otherwise.
	 */
	bool ResolveImports(LPVOID lpImage) noexcept;

	/**
	 *	Resolves a single import thunk table into its IAT.
	 *	\param lpImage : base address of the mapped image.
	 *	\param hModule : module exporting the imported symbols.
	 *	\param lpLibraryName : name of the exporting module (used for logging).
	 *	\param dLookupRva : RVA of the thunk table holding the names/ordinals.
	 *	\param dIatRva : RVA of the import address table to fill.
	 *	\return : true if all thunks were resolved, false otherwise.
	 */
	bool ResolveImportTable(LPVOID lpImage, HMODULE hModule, const char* lpLibraryName, DWORD_PTR dLookupRva, DWORD_PTR dIatRva) noexcept;
}

#endif
