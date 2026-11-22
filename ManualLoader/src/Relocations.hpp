#ifndef MANUALLOADER_DETAIL_RELOCATIONS_HPP
#define MANUALLOADER_DETAIL_RELOCATIONS_HPP

#include "Common.hpp"

namespace MemoryLoader::Detail
{
	/**
	 *	Applies the base relocations of a mapped PE image.
	 *	\param lpImage : base address of the mapped image.
	 *	\param dDelta : difference between the mapped base and the preferred base.
	 *	\return : true if all relocations were applied, false otherwise.
	 */
	bool ApplyRelocations(LPVOID lpImage, DWORD_PTR dDelta) noexcept;
}

#endif
