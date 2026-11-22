#ifndef MANUALLOADER_LOADER_HPP
#define MANUALLOADER_LOADER_HPP

#include <Windows.h>

/**
 *	Manual mapping of PE images (DLLs) in the current process.
 *
 *	The loader copies the image in memory, applies the base relocations,
 *	resolves the imports (IAT), runs the TLS callbacks and calls the entry
 *	point (DllMain). Exported functions can then be retrieved by name or by
 *	ordinal and the module can be unmapped with FreeDLL.
 */
namespace MemoryLoader
{
	/** Outcome of a load operation. */
	enum class Status
	{
		Success = 0,
		InvalidArgument,
		FileNotFound,
		InvalidPe,
		NotADll,
		ArchitectureMismatch,
		AllocationFailed,
		RelocationFailed,
		ImportResolutionFailed,
		EntryPointFailed,
	};

	/**
	 *	Loads a DLL into memory.
	 *	\param lpDLLPath : path of the DLL file.
	 *	\return : the module base address if successful, nullptr otherwise.
	 */
	LPVOID LoadDLL(const char* lpDLLPath);

	/**
	 *	Loads a DLL into memory and reports the outcome.
	 *	\param lpDLLPath : path of the DLL file.
	 *	\param pStatus : optional pointer receiving the operation status.
	 *	\return : the module base address if successful, nullptr otherwise.
	 */
	LPVOID LoadDLL(const char* lpDLLPath, Status* pStatus);

	/**
	 *	Retrieves an exported function by name.
	 *	\param lpModule : base address of the module.
	 *	\param lpFunctionName : name of the exported function.
	 *	\return : the function address if found, nullptr otherwise.
	 */
	LPVOID GetFunctionAddress(LPVOID lpModule, const char* lpFunctionName);

	/**
	 *	Retrieves an exported function by ordinal.
	 *	\param lpModule : base address of the module.
	 *	\param dOrdinal : ordinal of the exported function.
	 *	\return : the function address if found, nullptr otherwise.
	 */
	LPVOID GetFunctionAddressByOrdinal(LPVOID lpModule, DWORD_PTR dOrdinal);

	/**
	 *	Unmaps a module previously returned by LoadDLL.
	 *	\param lpModule : base address of the module.
	 *	\return : TRUE if successful, FALSE otherwise.
	 */
	BOOL FreeDLL(LPVOID lpModule);
}

#endif
