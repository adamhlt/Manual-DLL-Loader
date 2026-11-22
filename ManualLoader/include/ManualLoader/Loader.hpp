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
		DelayImportResolutionFailed,   // reserved: delay imports are resolved best-effort
		ExceptionTableFailed,
		ProtectionFailed,
		ModuleRegistrationFailed,
		EntryPointFailed,
	};

	/** Description of an exported symbol. */
	struct Export
	{
		const char* lpName;   // nullptr when the export has no name.
		DWORD dOrdinal;
		LPVOID lpAddress;
	};

	/** Options controlling how a module is mapped. */
	struct LoadOptions
	{
		/**
		 *	Registers the module in the PEB loader lists (InLoadOrder,
		 *	InMemoryOrder and InInitializationOrder), so it is enumerated like a
		 *	normally loaded module by CreateToolhelp32Snapshot / EnumProcessModules
		 *	/ LdrEnumerateLoadedModules.
		 *
		 *	Note: ntdll also keeps its own lookup tables (a module hash table and an
		 *	address index) that are undocumented and version specific; they are not
		 *	updated, so handle/name based lookups such as GetModuleFileName,
		 *	GetModuleHandleEx(FROM_ADDRESS) or RtlPcToFileHeader still do not
		 *	resolve the module.
		 *
		 *	When false (the default), the module stays completely invisible to the
		 *	OS, which is the classic manual-mapping behaviour and keeps it hidden.
		 */
		bool registerModule = false;
	};

	/**
	 *	Loads a DLL from a file.
	 *	\param lpDLLPath : path of the DLL file.
	 *	\return : the module base address if successful, nullptr otherwise.
	 */
	LPVOID LoadDLL(const char* lpDLLPath);
	LPVOID LoadDLL(const char* lpDLLPath, Status* pStatus);
	LPVOID LoadDLL(const char* lpDLLPath, const LoadOptions& options, Status* pStatus = nullptr);

	/**
	 *	Loads a DLL from an in-memory PE image.
	 *	\param lpImage : pointer to the raw PE image.
	 *	\param dImageSize : size of the raw PE image in bytes.
	 *	\return : the module base address if successful, nullptr otherwise.
	 */
	LPVOID LoadDLLFromMemory(LPCVOID lpImage, SIZE_T dImageSize);
	LPVOID LoadDLLFromMemory(LPCVOID lpImage, SIZE_T dImageSize, Status* pStatus);
	LPVOID LoadDLLFromMemory(LPCVOID lpImage, SIZE_T dImageSize, const LoadOptions& options, Status* pStatus = nullptr);

	/**
	 *	Registers an already mapped module in the PEB loader lists so it becomes
	 *	enumerable by the OS (CreateToolhelp32Snapshot, EnumProcessModules, ...).
	 *	\param lpModule : base address of the module.
	 *	\param lpName : name to expose; derived from the image when nullptr.
	 *	\return : true on success, false otherwise.
	 */
	bool RegisterModule(LPVOID lpModule, const char* lpName = nullptr);

	/**
	 *	Removes a module from the PEB loader lists so it becomes hidden again.
	 *	Safe to call on a module that was never registered.
	 */
	void UnregisterModule(LPVOID lpModule);

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
		static Module FromFile(const char* lpDLLPath, const LoadOptions& options, Status* pStatus = nullptr);

		/** Loads a module from an in-memory PE image. */
		static Module FromMemory(LPCVOID lpImage, SIZE_T dImageSize, Status* pStatus = nullptr);
		static Module FromMemory(LPCVOID lpImage, SIZE_T dImageSize, const LoadOptions& options, Status* pStatus = nullptr);

		bool IsValid() const noexcept;
		LPVOID Get() const noexcept;
		explicit operator bool() const noexcept;

		LPVOID GetFunction(const char* lpFunctionName) const;
		LPVOID GetFunctionByOrdinal(DWORD_PTR dOrdinal) const;
		std::vector<Export> GetExports() const;

		/** Registers the module in the PEB loader lists. */
		bool RegisterModule(const char* lpName = nullptr) const;

		/** Removes the module from the PEB loader lists. */
		void UnregisterModule() const;

		/** Relinquishes ownership; the caller becomes responsible for FreeDLL. */
		LPVOID Release() noexcept;

		/** Unmaps the module if it owns one. */
		void Reset() noexcept;

	private:
		LPVOID m_lpBase = nullptr;
	};
}

#endif
