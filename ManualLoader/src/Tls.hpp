#ifndef MANUALLOADER_DETAIL_TLS_HPP
#define MANUALLOADER_DETAIL_TLS_HPP

#include "Common.hpp"

namespace MemoryLoader::Detail
{
	/**
	 *	Runs the TLS callbacks of a mapped PE image.
	 *	\param lpImage : base address of the mapped image.
	 *	\param dwReason : reason passed to the callbacks (DLL_PROCESS_ATTACH / DETACH).
	 */
	void RunTlsCallbacks(LPVOID lpImage, DWORD dwReason) noexcept;
}

#endif
