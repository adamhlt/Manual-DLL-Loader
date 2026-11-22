#ifndef MANUALLOADER_DETAIL_EXPORTS_HPP
#define MANUALLOADER_DETAIL_EXPORTS_HPP

#include <vector>

#include "Common.hpp"
#include "ManualLoader/Loader.hpp"

namespace MemoryLoader::Detail
{
	/**
	 *	Resolves an export RVA to a callable address, following forwarders.
	 *	\param lpModule : base address of the module.
	 *	\param dFunctionRva : RVA of the export in the export address table.
	 *	\param exportDirectory : export data directory of the module.
	 *	\return : the resolved address, or nullptr on failure.
	 */
	LPVOID ResolveExportAddress(LPVOID lpModule, DWORD dFunctionRva, const IMAGE_DATA_DIRECTORY& exportDirectory) noexcept;

	/**
	 *	Enumerates the exports of a module.
	 *	\return : false if the module has no export directory, true otherwise.
	 */
	bool EnumerateExports(LPVOID lpModule, std::vector<Export>& exports);
}

#endif
