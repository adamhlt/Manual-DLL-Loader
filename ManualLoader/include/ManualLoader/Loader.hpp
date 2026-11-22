#ifndef MANUALLOADER_LOADER_HPP
#define MANUALLOADER_LOADER_HPP

#include <Windows.h>

#include <vector>

/**
 *	Manual mapping of PE images (DLLs) in the current process.
 *
 *	The loader copies the image in memory, applies the base relocations,
 *	resolves the imports (regular and delay-loaded), sets up the static TLS,
 *	runs the TLS callbacks, registers the exception table (x64) and calls the
 *	entry point (DllMain). Section protections are then restored from the PE
 *	characteristics. Exported functions can be retrieved by name or by ordinal
 *	and the module can be unmapped with FreeDLL.
 */
namespace MemoryLoader
{
	/** Severity of a log message. */
	enum class LogLevel
	{
		Debug = 0,
		Info,
		Warning,
		Error,
		Silent,
	};

	/** Receives a formatted log message. */
	using LogCallback = void (*)(LogLevel level, const char* lpMessage);

	/** Sets the minimum severity that is reported. */
	void SetLogLevel(LogLevel level) noexcept;

	/** Sets a custom log sink. Passing nullptr restores the default (stdout). */
	void SetLogCallback(LogCallback lpCallback) noexcept;

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
		DelayImportResolutionFailed,
		ExceptionTableFailed,
		ProtectionFailed,
		EntryPointFailed,
	};

	/** Description of an exported symbol. */
	struct Export
	{
		const char* lpName;   // nullptr when the export has no name.
		DWORD dOrdinal;
		LPVOID lpAddress;
	};

	/**
	 *	Loads a DLL from a file.
	 *	\param lpDLLPath : path of the DLL file.
	 *	\return : the module base address if successful, nullptr otherwise.
	 */
	LPVOID LoadDLL(const char* lpDLLPath);
	LPVOID LoadDLL(const char* lpDLLPath, Status* pStatus);

	/**
	 *	Loads a DLL from an in-memory PE image.
	 *	\param lpImage : pointer to the raw PE image.
	 *	\param dImageSize : size of the raw PE image in bytes.
	 *	\return : the module base address if successful, nullptr otherwise.
	 */
	LPVOID LoadDLLFromMemory(LPCVOID lpImage, SIZE_T dImageSize);
	LPVOID LoadDLLFromMemory(LPCVOID lpImage, SIZE_T dImageSize, Status* pStatus);

	/**
	 *	Retrieves an exported function by name. Forwarded exports are resolved.
	 *	\return : the function address if found, nullptr otherwise.
	 */
	LPVOID GetFunctionAddress(LPVOID lpModule, const char* lpFunctionName);

	/**
	 *	Retrieves an exported function by ordinal. Forwarded exports are resolved.
	 *	\return : the function address if found, nullptr otherwise.
	 */
	LPVOID GetFunctionAddressByOrdinal(LPVOID lpModule, DWORD_PTR dOrdinal);

	/**
	 *	Lists the exports of a module.
	 *	\return : false if the module has no export directory, true otherwise.
	 */
	bool GetExports(LPVOID lpModule, std::vector<Export>& exports);
	std::vector<Export> GetExports(LPVOID lpModule);

	/**
	 *	Runs the TLS callbacks of a module for the given reason.
	 *	Useful to replay DLL_THREAD_ATTACH / DLL_THREAD_DETACH for a new thread.
	 */
	void RunTlsCallbacks(LPVOID lpModule, DWORD dwReason);

	/**
	 *	Unmaps a module previously returned by a load function.
	 *	\return : TRUE if successful, FALSE otherwise.
	 */
	BOOL FreeDLL(LPVOID lpModule);

	/** RAII owner of a manually mapped module. */
	class Module
	{
	public:
		Module() = default;
		explicit Module(LPVOID lpBase) noexcept;
		~Module();

		Module(Module&& other) noexcept;
		Module& operator=(Module&& other) noexcept;
		Module(const Module&) = delete;
		Module& operator=(const Module&) = delete;

		/** Loads a module from a file. */
		static Module FromFile(const char* lpDLLPath, Status* pStatus = nullptr);

		/** Loads a module from an in-memory PE image. */
		static Module FromMemory(LPCVOID lpImage, SIZE_T dImageSize, Status* pStatus = nullptr);

		bool IsValid() const noexcept;
		LPVOID Get() const noexcept;
		explicit operator bool() const noexcept;

		LPVOID GetFunction(const char* lpFunctionName) const;
		LPVOID GetFunctionByOrdinal(DWORD_PTR dOrdinal) const;
		std::vector<Export> GetExports() const;

		/** Relinquishes ownership; the caller becomes responsible for FreeDLL. */
		LPVOID Release() noexcept;

		/** Unmaps the module if it owns one. */
		void Reset() noexcept;

	private:
		LPVOID m_lpBase = nullptr;
	};
}

#endif
