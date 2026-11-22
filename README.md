```
        __  ___                        __   ____  __    __       __                    __       
       /  |/  /___ _____  __  ______ _/ /  / __ \/ /   / /      / /   ____  ____ _____/ /__  _____
      / /|_/ / __ `/ __ \/ / / / __ `/ /  / / / / /   / /      / /   / __ \/ __ `/ __  / _ \/ ___/
     / /  / / /_/ / / / / /_/ / /_/ / /  / /_/ / /___/ /___   / /___/ /_/ / /_/ / /_/ /  __/ /
    /_/  /_/\__,_/_/ /_/\__,_/\__,_/_/  /_____/_____/_____/  /_____/\____/\__,_/\__,_/\___/_/
                                                                                       
                                                                                       
                           Custom LoadLibrary / GetProcAddress (x86 / x64)  
                             Load DLL and retrieve functions manually 
```
<p align="center">
    <img src="https://img.shields.io/badge/language-C%2B%2B-%23f34b7d.svg?style=for-the-badge&logo=appveyor" alt="C++">
    <img src="https://img.shields.io/badge/platform-Windows-0078d7.svg?style=for-the-badge&logo=appveyor" alt="Windows">
    <img src="https://img.shields.io/badge/arch-x86-red.svg?style=for-the-badge&logo=appveyor" alt="x86">
    <img src="https://img.shields.io/badge/arch-x64-green.svg?style=for-the-badge&logo=appveyor" alt="x64">
</p>

## :open_book: Project Overview :

#### Custom LoadLibrary / GetProcAddress

This is a custom implementation of different Windows functions : 

- LoadLibraryA

- GetProcAddress

- FreeLibrary

You can manualy map DLL into your program, retrieve functions by name or ordinal and free the library.

The loader perform the relocations, and it is fully functionnal with x86 and x64 PE images.

Loading steps :

1. Copy PE image in memory
2. Perform the relocations
3. Resolve imports (IAT), including delay-loaded imports
4. Optionally register the module in the PEB loader lists
5. Set up the static TLS and execute the TLS callbacks
6. Register the exception table (x64, so SEH / C++ exceptions work)
7. Restore the section protections from the PE characteristics
8. Execute DLL's entry point 

Features :

- Load a DLL from a file or from an in-memory buffer.
- Optional PEB registration: by default a mapped module stays hidden, but it can
  be registered in the PEB loader lists (visible to `CreateToolhelp32Snapshot` /
  `EnumProcessModules`) and unregistered again at any time.
- Resolve regular and delay-loaded imports. Delay-loaded imports are resolved
  eagerly when possible; unavailable ones are left to the image's own delay-load
  helper.
- Resolve forwarded exports (`"OTHERDLL.Function"`).
- Enumerate the exports of a module.
- RAII `MemoryLoader::Module` wrapper.
- Configurable logging (levels and custom callback).
- Per-section memory protection instead of `PAGE_EXECUTE_READWRITE` everywhere.

The GetFunctionAddress can also be used with a library imported with LoadLibraryA official Windows function.

## :file_folder: Project Layout

```
Manual-DLL-Loader/
├── ManualLoader.sln        Visual Studio solution (open this file)
├── ManualLoader/           Loader library (static lib)
│   ├── include/ManualLoader/Loader.hpp   Public API
│   └── src/                Implementation (PeImage, Relocations, Imports, DelayImports,
│                           Exports, Exceptions, Protection, Tls, ModuleRegistration, Log)
├── Demo/                   Console sample using the loader
└── LoaderCLI/              Command line tool to inspect a DLL
```

The loader is built as a reusable static library (`ManualLoader`); the `Demo` and
`LoaderCLI` projects are console applications that reference it.

## :rocket: Getting Started
### Visual Studio :
1. Open the solution file `ManualLoader.sln` at the root of the repository.
2. Build the solution in Release (x86 or x64). The `Demo` project links against the `ManualLoader` library.

> **Note** <br>
> The loader can be compiled in x86 or x64.

### Command line tool

```
LoaderCLI [options] <path-to-dll> [export]

  -l, --list      List the exports (default when no export is given).
  -c, --call      Call the given export as void(*)(void).
  -v, --verbose   Enable debug logging.
  -q, --quiet     Only report errors.
  -h, --help      Show the help message.
```

Example :

```
LoaderCLI -l C:\Windows\System32\version.dll
```

## :test_tube: Example

You can import DLL and functions easily like when you use LoadLibraryA and GetProcAddress.

```c++
//Function pointer
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

> **Note** <br>
> `LoadDLL` has an overload taking a `MemoryLoader::Status*` that reports the
> precise reason of a failure (invalid PE, wrong architecture, unresolved import, ...).
> The verbosity of the loader output can be tuned with `MemoryLoader::SetLogLevel`.

### RAII wrapper and other entry points

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

// Redirect the loader output to a custom sink.
MemoryLoader::SetLogCallback([](MemoryLoader::LogLevel level, const char* message)
{
	// ...
});
```

### Hiding / exposing a module

A mapped module is hidden from the OS by default. It can be registered in the
PEB loader lists when it needs to be enumerated:

```c++
MemoryLoader::LoadOptions options;
options.registerModule = true;   // false by default: the module stays hidden

MemoryLoader::Module module = MemoryLoader::Module::FromFile("plugin.dll", options);

// Hide it again, or expose it at runtime.
module.UnregisterModule();
module.RegisterModule("plugin.dll");
```

> **Note** <br>
> Registering the module populates the three PEB loader lists, so it shows up in
> `CreateToolhelp32Snapshot` / `EnumProcessModules`. The undocumented, version
> specific lookup tables kept by ntdll (module hash table and address index) are
> not updated, so `GetModuleFileName`, `GetModuleHandleEx(FROM_ADDRESS)` and
> `RtlPcToFileHeader` still do not resolve the module.

## :warning: Known limitations

Mapping a PE image without involving the OS loader has a few consequences:

- **Module recognition.** The mapped module is unknown to ntdll's internal
  lookup tables, so `GetModuleFileName`, `GetModuleHandleEx(FROM_ADDRESS)` and
  `RtlPcToFileHeader` do not resolve it. No documented API can register an
  existing memory region as a module; only the PEB loader lists can be populated
  (see `LoadOptions::registerModule`).

- **Resources work.** `FindResource`, `LoadString`, `LoadImage` and
  `SizeofResource` read the resource directory straight from the mapped base, so
  they work on a hidden, non-registered module.

- **Delay-loaded imports** are resolved eagerly when possible. When a
  delay-loaded dependency or symbol is unavailable, the thunk is left untouched
  so the image's own delay-load helper resolves it on demand; the load is not
  aborted. VA-based descriptors (Visual Studio 2015 and earlier) are skipped.

- **Static TLS** is initialized for the thread that performs the load only.
  Threads created afterwards do not receive a TLS block, which would require
  hooking thread creation.

- **System DLLs with process-wide one-time initialization** cannot be mapped.
  `user32.dll` for instance connects to win32k, and its `DllMain` refuses to
  initialize when the module is not the one the OS loaded. Load such DLLs with
  the normal `LoadLibrary` instead.

### Test DLL

https://user-images.githubusercontent.com/48086737/156903481-c35ad388-f8ff-49d7-9f93-dd428670d00f.mp4

### [ImGui Standalone](https://github.com/adamhlt/ImGui-Standalone)

https://github.com/adamhlt/Manual-DLL-Loader/assets/48086737/79897d57-3084-4163-9c0f-824962e1c7e5
