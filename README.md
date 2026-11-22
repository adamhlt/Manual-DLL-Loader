<div align="center">

# Manual DLL Loader

**Custom LoadLibrary / GetProcAddress in C++ (x86 / x64), map a DLL in memory and call its exports**

![Language](https://img.shields.io/badge/C%2B%2B-16171C?logo=cplusplus)
![Platform](https://img.shields.io/badge/Windows-16171C)
![Arch](https://img.shields.io/badge/x86%20%7C%20x64-16171C)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-16171C)](LICENSE)

</div>

---

Manual DLL Loader is a custom implementation of `LoadLibraryA`, `GetProcAddress` and `FreeLibrary` that maps a PE image in memory without going through the OS loader.

The image is copied in memory, the relocations are applied, the imports (including the delay-loaded ones) are resolved, the static TLS is set up, the TLS callbacks are run, the exception table is registered, the section protections are restored from the PE characteristics and the entry point is called. Exported functions are then retrieved by name or by ordinal. The same code base handles x86 and x64 images.

`GetFunctionAddress` can also be used on a library imported with the official `LoadLibraryA`.

### TEST FILE (DLL)
https://user-images.githubusercontent.com/48086737/156903481-c35ad388-f8ff-49d7-9f93-dd428670d00f.mp4

### [ImGui Standalone](https://github.com/adamhlt/ImGui-Standalone)
https://github.com/adamhlt/Manual-DLL-Loader/assets/48086737/79897d57-3084-4163-9c0f-824962e1c7e5

## Features

**Mapping**
- Map a DLL from a file or from an in-memory buffer
- Copy the headers and the sections, then apply the base relocations (`ABSOLUTE`, `HIGHLOW`, `DIR64`, `HIGH`, `LOW`)
- Restore the section protections from the PE characteristics instead of a single `PAGE_EXECUTE_READWRITE`
- Optional PEB registration: the module stays hidden by default and can be exposed or hidden again at runtime

**Imports and exports**
- Resolve the import address table (IAT)
- Resolve delay-loaded imports (best effort)
- Resolve forwarded exports (`"OTHERDLL.Function"`)
- Retrieve an export by name or by ordinal
- Enumerate every export of a module

**Initialization**
- Initialize the static TLS and run the TLS callbacks
- Register the exception table on x64 so SEH and C++ exceptions work

**API**
- RAII `MemoryLoader::Module` wrapper
- `Status` reporting the exact reason of a failure
- Configurable logging (levels and custom callback)

## Usage

### Library

```c++
#include "ManualLoader/Loader.hpp"

// Function pointer
using MessageFncPtr = void (*)();

int main()
{
	MemoryLoader::Status status = MemoryLoader::Status::Success;
	const auto lpModule = MemoryLoader::LoadDLL("test.dll", &status);
	if (lpModule == nullptr)
		return -1;

	auto MessageFnc = (MessageFncPtr)MemoryLoader::GetFunctionAddress(lpModule, "Message");
	if (MessageFnc == nullptr)
		return -1;

	MessageFnc();

	MessageFnc = (MessageFncPtr)MemoryLoader::GetFunctionAddressByOrdinal(lpModule, 1);
	if (MessageFnc == nullptr)
		return -1;

	MessageFnc();

	MemoryLoader::FreeDLL(lpModule);

	return 0;
}
```

> **Note**
> `LoadDLL` has an overload taking a `MemoryLoader::Status*` that reports the precise reason of a failure (invalid PE, wrong architecture, unresolved import, ...), and one taking a `MemoryLoader::LoadOptions` to enable the PEB registration. The verbosity of the loader output can be tuned with `MemoryLoader::SetLogLevel`.

### RAII wrapper

```c++
// The module is unmapped automatically when it goes out of scope.
const MemoryLoader::Module module = MemoryLoader::Module::FromFile("test.dll");

// Load from an in-memory buffer instead of a file.
// const MemoryLoader::Module module = MemoryLoader::Module::FromMemory(bytes, size);

if (!module)
	return -1;

const auto MessageFnc = (MessageFncPtr)module.GetFunction("Message");

// Enumerate every export of the module.
for (const auto& entry : module.GetExports())
{
	// entry.lpName, entry.dOrdinal, entry.lpAddress
}
```

### Hiding / exposing a module

A mapped module is hidden from the OS by default. It can be registered in the PEB loader lists when it needs to be enumerated, and hidden again at any time.

```c++
MemoryLoader::LoadOptions options;
options.registerModule = true;   // false by default: the module stays hidden

MemoryLoader::Module module = MemoryLoader::Module::FromFile("plugin.dll", options);

module.UnregisterModule();
module.RegisterModule("plugin.dll");
```

### Command line tool

```
LoaderCLI [options] <path-to-dll> [export]

  -l, --list      List the exports (default when no export is given).
  -c, --call      Call the given export as void(*)(void).
  -v, --verbose   Enable debug logging.
  -q, --quiet     Only report errors.
  -h, --help      Show the help message.
```

```
LoaderCLI -l C:\Windows\System32\version.dll
```

## Build

1. Open `ManualLoader.sln` in Visual Studio (C++17).
2. Build in Release (x86 or x64).

- **Output:** the loader is built as a static library (`ManualLoader`), used by the `Demo` and `LoaderCLI` console applications
- **Architecture:** the x86 build maps x86 images and the x64 build maps x64 images

## Known limitations

Mapping a PE image without involving the OS loader has a few consequences.

- **Module recognition.** The mapped module is unknown to ntdll's internal lookup tables, so `GetModuleFileName`, `GetModuleHandleEx(FROM_ADDRESS)` and `RtlPcToFileHeader` do not resolve it. No documented API can register an existing memory region as a module; only the PEB loader lists can be populated (see `LoadOptions::registerModule`), which makes the module visible to `CreateToolhelp32Snapshot` / `EnumProcessModules`.

- **Resources work.** `FindResource`, `LoadString`, `LoadImage` and `SizeofResource` read the resource directory straight from the mapped base, so they work on a hidden, non-registered module.

- **Delay-loaded imports** are resolved eagerly when possible. When a delay-loaded dependency or symbol is unavailable, the thunk is left untouched so the image's own delay-load helper resolves it on demand; the load is not aborted. VA-based descriptors (Visual Studio 2015 and earlier) are skipped.

- **Static TLS** is initialized for the thread that performs the load only. Threads created afterwards do not receive a TLS block, which would require hooking thread creation.

- **System DLLs with process-wide one-time initialization** cannot be mapped. `user32.dll` for instance connects to win32k, and its `DllMain` refuses to initialize when the module is not the one the OS loaded. Load such DLLs with the normal `LoadLibrary` instead.

## License

This project is licensed under the [GNU GPLv3](LICENSE).
