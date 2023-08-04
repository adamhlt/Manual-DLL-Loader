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
3. Resolve imports (IAT)
4. Execute TLS callbacks
5. Execute DLL's entry point 

The GetFunctionAddress can also be used with a library imported with LoadLibraryA official Windows function.

## :rocket: Getting Started
### Visual Studio :
1. Open the solution file (.sln).
2. Build the project in Release (x86 or x64)

> **Note** <br>
> The loader can be compiled in x86 or x64.

## :test_tube: Example

You can import DLL and functions easily like when you use LoadLibraryA and GetProcAddress.

```c++
//Function pointer
using MessageFncPtr = void (*)();

int main()
{
	const auto lpModule = MemoryLoader::LoadDLL((LPSTR)"test.dll");
	if (lpModule == nullptr)
		return -1;

	auto MessageFnc = (MessageFncPtr)MemoryLoader::GetFunctionAddress((LPVOID)lpModule, (const LPSTR)"Message");
	if (MessageFnc == nullptr)
		return -1;

	MessageFnc();

	MessageFnc = (MessageFncPtr)MemoryLoader::GetFunctionAddressByOrdinal((LPVOID)lpModule, 1);
	if (MessageFnc == nullptr)
		return -1;

	MessageFnc();

	MemoryLoader::FreeDLL(lpModule);

	return 0;
}
```

### Test DLL

https://user-images.githubusercontent.com/48086737/156903481-c35ad388-f8ff-49d7-9f93-dd428670d00f.mp4

### [ImGui Standalone](https://github.com/adamhlt/ImGui-Standalone)

https://github.com/adamhlt/Manual-DLL-Loader/assets/48086737/79897d57-3084-4163-9c0f-824962e1c7e5
