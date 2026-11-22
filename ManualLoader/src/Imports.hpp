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
}

#endif
