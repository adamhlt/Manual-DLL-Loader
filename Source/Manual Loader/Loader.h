#ifndef LOADER_H
#define LOADER_H

#include <cstdio>
#include <Windows.h>

//dllmain pointer
using dllmain = BOOL(WINAPI*)(HINSTANCE dll, DWORD reason, LPVOID reserved);

//Structure relocation entry based on : https://docs.microsoft.com/fr-fr/windows/win32/debug/pe-format#the-reloc-section-image-only
typedef struct IMAGE_RELOCATION_ENTRY {
	WORD Offset : 12;
	WORD Type : 4;
} IMAGE_RELOCATION_ENTRY, * PIMAGE_RELOCATION_ENTRY;

class MemoryLoader
{
public:
	static LPVOID LoadDLL(const LPSTR lpDLLPath);
	static LPVOID GetFunctionAddress(const LPVOID lpModule, const LPSTR lpFunctionName);
	static LPVOID GetFunctionAddressByOrdinal(const LPVOID lpModule, const DWORD_PTR dOrdinal);
	static BOOL FreeDLL(const LPVOID lpModule);

private:
	static HANDLE GetFileContent(const LPSTR lpFilePath);
	static BOOL IsValidPE(const LPVOID lpImage);
	static BOOL IsDLL(const LPVOID hDLLData);
	static BOOL IsValidArch(const LPVOID lpImage);
	static DWORD_PTR GetImageSize(const LPVOID lpImage);
	static BOOL HasCallbacks(const LPVOID lpImage);
};

#endif