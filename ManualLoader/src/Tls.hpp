#ifndef MANUALLOADER_DETAIL_TLS_HPP
#define MANUALLOADER_DETAIL_TLS_HPP

#include "Common.hpp"

namespace MemoryLoader::Detail
{
	/**
	 *	Initializes the static TLS of a mapped image: allocates a TLS index and,
	 *	for the current thread, a copy of the TLS template.
	 *	\param lpImage : base address of the mapped image.
	 */
	void InitializeStaticTls(LPVOID lpImage) noexcept;

	/**
	 *	Releases the static TLS allocated by InitializeStaticTls.
	 *	\param lpImage : base address of the mapped image.
	 */
	void CleanupStaticTls(LPVOID lpImage) noexcept;

	/**
	 *	Runs the TLS callbacks of a mapped image.
	 *	\param lpImage : base address of the mapped image.
	 *	\param dwReason : reason passed to the callbacks (DLL_PROCESS_ATTACH / DETACH, ...).
	 */
	void RunTlsCallbacks(LPVOID lpImage, DWORD dwReason) noexcept;
}

#endif
