#ifndef MANUALLOADER_DETAIL_EXCEPTIONS_HPP
#define MANUALLOADER_DETAIL_EXCEPTIONS_HPP

#include "Common.hpp"

namespace MemoryLoader::Detail
{
	/**
	 *	Registers the exception table (RUNTIME_FUNCTION array) of a mapped image.
	 *	Only meaningful on x64; a no-op elsewhere.
	 *	\return : true on success, false otherwise.
	 */
	bool RegisterExceptionTable(LPVOID lpImage) noexcept;

	/** Unregisters the exception table of a mapped image. Only meaningful on x64. */
	void UnregisterExceptionTable(LPVOID lpImage) noexcept;
}

#endif
