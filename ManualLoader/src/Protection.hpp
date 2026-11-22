#ifndef MANUALLOADER_DETAIL_PROTECTION_HPP
#define MANUALLOADER_DETAIL_PROTECTION_HPP

#include "Common.hpp"

namespace MemoryLoader::Detail
{
	/**
	 *	Restores the memory protection of each section from its PE characteristics.
	 *	The headers are mapped read-only.
	 *	\param lpImage : base address of the mapped image.
	 *	\return : true on success, false otherwise.
	 */
	bool ApplySectionProtections(LPVOID lpImage) noexcept;
}

#endif
