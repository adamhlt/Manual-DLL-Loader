#ifndef MANUALLOADER_DETAIL_DELAYIMPORTS_HPP
#define MANUALLOADER_DETAIL_DELAYIMPORTS_HPP

#include "Common.hpp"

namespace MemoryLoader::Detail
{
	/**
	 *	Resolves the delay-loaded imports of a mapped PE image.
	 *	\param lpImage : base address of the mapped image.
	 *	\return : true if all delay imports were resolved, false otherwise.
	 */
	bool ResolveDelayImports(LPVOID lpImage) noexcept;
}

#endif
