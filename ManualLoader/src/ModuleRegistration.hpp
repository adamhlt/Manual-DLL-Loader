#ifndef MANUALLOADER_DETAIL_MODULEREGISTRATION_HPP
#define MANUALLOADER_DETAIL_MODULEREGISTRATION_HPP

#include "Common.hpp"

namespace MemoryLoader::Detail
{
	/**
	 *	Registers a mapped image in the PEB loader lists so that the OS and the
	 *	Win32 APIs treat it as a normally loaded module.
	 *	\param lpImage : base address of the mapped image.
	 *	\param lpName : module name to expose (file path or plain name).
	 *	\return : true on success, false otherwise.
	 */
	bool RegisterModule(LPVOID lpImage, const char* lpName) noexcept;

	/** Removes a previously registered image from the PEB loader lists. */
	void UnregisterModule(LPVOID lpImage) noexcept;
}

#endif
