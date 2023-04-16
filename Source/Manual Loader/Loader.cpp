#include "Loader.h"

/**
 *	Function to retrieve the PE file content.
 *	\param lpFilePath : path of the PE file.
 *	\return : address of the content in the explorer memory.
 */
HANDLE MemoryLoader::GetFileContent(const LPSTR lpFilePath)
{
	const HANDLE hFile = CreateFileA(lpFilePath, GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("[-] An error occured when trying to open the PE file !\n");
		CloseHandle(hFile);
		return nullptr;
	}

	const DWORD dFileSize = GetFileSize(hFile, nullptr);
	if (dFileSize == INVALID_FILE_SIZE)
	{
		printf("[-] An error occured when trying to get the PE file size !\n");
		CloseHandle(hFile);
		return nullptr;
	}

	const HANDLE hFileContent = HeapAlloc(GetProcessHeap(), 0, dFileSize);
	if (hFileContent == INVALID_HANDLE_VALUE)
	{
		printf("[-] An error occured when trying to allocate memory for the PE file content !\n");
		CloseHandle(hFile);
		CloseHandle(hFileContent);
		return nullptr;
	}

	const BOOL bFileRead = ReadFile(hFile, hFileContent, dFileSize, nullptr, nullptr);
	if (!bFileRead)
	{
		printf("[-] An error occured when trying to read the PE file content !\n");

		CloseHandle(hFile);
		if (hFileContent != nullptr)
			CloseHandle(hFileContent);

		return nullptr;
	}

	CloseHandle(hFile);
	return hFileContent;
}

/**
 *	Function to check if the image is a valid PE file.
 *	\param lpImage : PE image data.
 *	\return : TRUE if the image is a valid PE else no.
 */
BOOL MemoryLoader::IsValidPE(const LPVOID lpImage)
{
	const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
	const auto lpImageNTHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);
	if (lpImageNTHeader->Signature == IMAGE_NT_SIGNATURE)
		return TRUE;

	return FALSE;
}

/**
 *	Function to identify if the PE file is a DLL.
 *	\param hDLLData : DLL image.
 *	\return : true if the image is a DLL else false.
 */
BOOL MemoryLoader::IsDLL(const LPVOID hDLLData)
{
	const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)(hDLLData);
	const auto lpImageNtHeader = (PIMAGE_NT_HEADERS32)((DWORD_PTR)hDLLData + lpImageDOSHeader->e_lfanew);

	if (lpImageNtHeader->FileHeader.Characteristics & IMAGE_FILE_DLL)
		return TRUE;

	return FALSE;
}

/**
 *	Function to check if the image has the same arch.
 *	\param lpImage : PE image data.
 *	\return : TRUE if the image has the arch else FALSE.
 */
BOOL MemoryLoader::IsValidArch(const LPVOID lpImage)
{
	const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
	const auto lpImageNTHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);
	if (lpImageNTHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR_MAGIC)
		return TRUE;

	return FALSE;
}

/**
 *	Function to retrieve the size of the PE image.
 *	\param lpImage : PE image data.
 *	\return : the size of the PE image.
 */
DWORD_PTR MemoryLoader::GetImageSize(const LPVOID lpImage)
{
	const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
	const auto lpImageNTHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);
	return lpImageNTHeader->OptionalHeader.SizeOfImage;
}

BOOL MemoryLoader::HasCallbacks(const LPVOID lpImage)
{
	const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
	const auto lpImageNTHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)lpImage + lpImageDOSHeader->e_lfanew);
	const DWORD_PTR dVirtualAddress = lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;

	return dVirtualAddress != 0;
}

/**
 *	Function to load a DLL in memory
 *	\param lpDLLPath : path of the DLL file.
 *	\return : DLL address if success else nullptr.
 */
LPVOID MemoryLoader::LoadDLL(const LPSTR lpDLLPath)
{
	printf("[+] DLL LOADER\n");

	const HANDLE hDLLData = GetFileContent(lpDLLPath);
	if (hDLLData == INVALID_HANDLE_VALUE || hDLLData == nullptr)
	{
		printf("[-] An error is occured when trying to get DLL's data !\n");
		return nullptr;
	}

	printf("[+] DLL's data at 0x%p\n", (LPVOID)hDLLData);

	if (!IsValidPE(hDLLData))
	{
		printf("[-] The DLL is not a valid PE file !\n");

		if (hDLLData != nullptr)
			HeapFree(GetProcessHeap(), 0, hDLLData);
		return nullptr;
	}

	printf("[+] The PE image is valid.\n");

	if (!IsDLL(hDLLData))
	{
		printf("[-] The PE file is not a DLL !\n");
		return nullptr;
	}

	printf("[+] The PE image correspond to a DLL.\n");

	if (!IsValidArch(hDLLData))
	{
		printf("[-] The architectures are not compatible !\n");
		return nullptr;
	}

	printf("[+] The architectures are compatible.\n");

	const DWORD_PTR dImageSize = GetImageSize(hDLLData);

	printf("[+] PE image size : 0x%x\n", (UINT)dImageSize);

	const LPVOID lpAllocAddress = VirtualAlloc(nullptr, dImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (lpAllocAddress == nullptr)
	{
		printf("[-] An error is occured when tying to allocate the DLL's memory !\n");
		return nullptr;
	}

	printf("[+] DLL memory allocated at 0x%p\n", (LPVOID)lpAllocAddress);

	const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)hDLLData;
	const auto lpImageNTHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);
	const auto lpImageSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)lpImageNTHeader + 4 + sizeof(IMAGE_FILE_HEADER) + lpImageNTHeader->FileHeader.SizeOfOptionalHeader);

	const DWORD_PTR dDeltaAddress = (DWORD_PTR)lpAllocAddress - lpImageNTHeader->OptionalHeader.ImageBase;

	lpImageNTHeader->OptionalHeader.ImageBase = (DWORD_PTR)lpAllocAddress;

	RtlCopyMemory(lpAllocAddress, hDLLData, lpImageNTHeader->OptionalHeader.SizeOfHeaders);

	const IMAGE_DATA_DIRECTORY ImageDataReloc = lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	const IMAGE_DATA_DIRECTORY ImageDataImport = lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

	PIMAGE_SECTION_HEADER lpImageRelocHeader = nullptr;
	PIMAGE_SECTION_HEADER lpImageImportHeader = nullptr;
	for (int i = 0; i < lpImageNTHeader->FileHeader.NumberOfSections; i++)
	{
		const auto lpCurrentSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)lpImageSectionHeader + (i * sizeof(IMAGE_SECTION_HEADER)));
		if (ImageDataReloc.VirtualAddress >= lpCurrentSectionHeader->VirtualAddress && ImageDataReloc.VirtualAddress < (lpCurrentSectionHeader->VirtualAddress + lpCurrentSectionHeader->Misc.VirtualSize))
			lpImageRelocHeader = lpCurrentSectionHeader;
		if (ImageDataImport.VirtualAddress >= lpCurrentSectionHeader->VirtualAddress && ImageDataImport.VirtualAddress < (lpCurrentSectionHeader->VirtualAddress + lpCurrentSectionHeader->Misc.VirtualSize))
			lpImageImportHeader = lpCurrentSectionHeader;
		RtlCopyMemory((LPVOID)((DWORD_PTR)lpAllocAddress + lpCurrentSectionHeader->VirtualAddress), (LPVOID)((DWORD_PTR)hDLLData + lpCurrentSectionHeader->PointerToRawData), lpCurrentSectionHeader->SizeOfRawData);
		printf("[+] The section %s has been writed.\n", (LPSTR)lpCurrentSectionHeader->Name);
	}

	if (lpImageRelocHeader == nullptr)
	{
		printf("[-] An error is occured when tying to get the relocation section !\n");
		return nullptr;
	}

	if (lpImageImportHeader == nullptr)
	{
		printf("[-] An error is occured when tying to get the import section !\n");
		return nullptr;
	}

	printf("[+] Relocation in %s section.\n", (LPSTR)lpImageRelocHeader->Name);
	printf("[+] Import in %s section.\n", (LPSTR)lpImageImportHeader->Name);

	DWORD_PTR RelocOffset = 0;

	while (RelocOffset < ImageDataReloc.Size)
	{
		const auto lpImageBaseRelocation = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)hDLLData + lpImageRelocHeader->PointerToRawData + RelocOffset);
		RelocOffset += sizeof(IMAGE_BASE_RELOCATION);
		const DWORD_PTR NumberOfEntries = (lpImageBaseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOCATION_ENTRY);
		for (DWORD_PTR i = 0; i < NumberOfEntries; i++)
		{
			const auto lpImageRelocationEntry = (PIMAGE_RELOCATION_ENTRY)((DWORD_PTR)hDLLData + lpImageRelocHeader->PointerToRawData + RelocOffset);
			RelocOffset += sizeof(IMAGE_RELOCATION_ENTRY);

			if (lpImageRelocationEntry->Type == 0)
				continue;

			const DWORD_PTR AddressLocation = (DWORD_PTR)lpAllocAddress + lpImageBaseRelocation->VirtualAddress + lpImageRelocationEntry->Offset;

			DWORD_PTR PatchedAddress = 0;

			RtlCopyMemory((LPVOID)&PatchedAddress, (LPVOID)AddressLocation, sizeof(DWORD_PTR));

			PatchedAddress += dDeltaAddress;

			RtlCopyMemory((LPVOID)AddressLocation, (LPVOID)&PatchedAddress, sizeof(DWORD_PTR));
		}
	}

	auto lpImageImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD_PTR)lpAllocAddress + lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	if (lpImageImportDescriptor == nullptr)
	{
		printf("[-] An error is occured when tying to get the import descriptor !\n");
		return nullptr;
	}

	while(lpImageImportDescriptor->Name != 0)
	{
		const auto lpLibraryName = (LPSTR)((DWORD_PTR)lpAllocAddress + lpImageImportDescriptor->Name);
		const HMODULE hModule = LoadLibraryA(lpLibraryName);
		if (hModule == nullptr)
		{
			printf("[-] An error is occured when tying to load %s DLL !\n", lpLibraryName);
			return nullptr;
		}

		printf("[+] Loading %s\n", lpLibraryName);

		auto lpThunkData = (PIMAGE_THUNK_DATA)((DWORD_PTR)lpAllocAddress + lpImageImportDescriptor->FirstThunk);
		while (lpThunkData->u1.AddressOfData != 0)
		{
			if (IMAGE_SNAP_BY_ORDINAL(lpThunkData->u1.Ordinal))
			{
				const auto functionOrdinal = (UINT)IMAGE_ORDINAL(lpThunkData->u1.Ordinal);
				lpThunkData->u1.Function = (DWORD_PTR)GetProcAddress(hModule, MAKEINTRESOURCEA(functionOrdinal));
				printf("[+]\tFunction Ordinal %u\n", functionOrdinal);
			}
			else
			{
				const auto lpData = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)lpAllocAddress + lpThunkData->u1.AddressOfData);
				const auto functionAddress = (DWORD_PTR)GetProcAddress(hModule, lpData->Name);
				lpThunkData->u1.Function = functionAddress;
				printf("[+]\tFunction %s\n", (LPSTR)lpData->Name);
			}

			lpThunkData++;
		}

		lpImageImportDescriptor++;
	}

	if (HasCallbacks(hDLLData))
	{
		const auto lpImageTLSDirectory = (PIMAGE_TLS_DIRECTORY)((DWORD_PTR)lpAllocAddress + lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		auto lpCallbackArray = (PIMAGE_TLS_CALLBACK*)lpImageTLSDirectory->AddressOfCallBacks;

		while (*lpCallbackArray != nullptr)
		{
			const auto lpImageCallback = *lpCallbackArray;
			lpImageCallback(hDLLData, DLL_PROCESS_ATTACH, nullptr);
			lpCallbackArray++;
		}

		printf("[+] TLS callbacks executed (DLL_PROCESS_ATTACH).\n");
	}

	const auto main = (dllmain)((DWORD_PTR)lpAllocAddress + lpImageNTHeader->OptionalHeader.AddressOfEntryPoint);
	const BOOL result = main((HINSTANCE)lpAllocAddress, DLL_PROCESS_ATTACH, nullptr);
	if (!result)
	{
		printf("[-] An error is occured when trying to call the DLL's entrypoint !\n");
		return nullptr;
	}

	HeapFree(GetProcessHeap(), 0, hDLLData);

	printf("[+] dllmain have been called (DLL_PROCESS_ATTACH).\n");
	printf("[+] DLL loaded successfully.\n");

	return (LPVOID)lpAllocAddress;
}

/**
 *	Function to find function in the DLL.
 *	\param lpModule : address of the DLL.
 *	\param lpFunctionName : name of the function.
 *	\return : address of the function if success else nullptr.
 */
LPVOID MemoryLoader::GetFunctionAddress(const LPVOID lpModule, const LPSTR lpFunctionName)
{
	const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpModule;
	const auto lpImageNTHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);
	if (lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0)
		return nullptr;

	const auto lpImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)lpModule + lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	const DWORD_PTR dNumberOfNames = lpImageExportDirectory->NumberOfNames;

	for (int i = 0; i < (int)dNumberOfNames; i++)
	{
		const auto lpCurrentFunctionName = (LPSTR)(((DWORD*)(lpImageExportDirectory->AddressOfNames + (DWORD_PTR)lpModule))[i] + (DWORD_PTR)lpModule);
		const auto lpCurrentOridnal = ((WORD*)(lpImageExportDirectory->AddressOfNameOrdinals + (DWORD_PTR)lpModule))[i];
		const auto addRVA = ((DWORD*)((DWORD_PTR)lpModule + lpImageExportDirectory->AddressOfFunctions))[lpCurrentOridnal];
		if (strcmp(lpCurrentFunctionName, lpFunctionName) == 0)
			return (LPVOID)((DWORD_PTR)lpModule + addRVA);
	}

	return nullptr;
}

/**
 *	Function to retrieve function address by using ordinal.
 *	\param lpModule : address of the DLL.
 *	\param dOrdinal : ordinal of the function.
 *	\return : the address of the function.
 */
LPVOID MemoryLoader::GetFunctionAddressByOrdinal(const LPVOID lpModule, const DWORD_PTR dOrdinal)
{
	const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpModule;
	const auto lpImageNTHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);
	if (lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0)
		return nullptr;

	const auto lpImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)lpModule + lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	const auto addRVA = ((DWORD*)((DWORD_PTR)lpModule + lpImageExportDirectory->AddressOfFunctions))[dOrdinal];
	return (LPVOID)((DWORD_PTR)lpModule + addRVA);
}

/**
 *	Function to free the DLL.
 *	\param lpModule : address of the loaded DLL.
 *	\return : FALSE if it failed else TRUE.
 */
BOOL MemoryLoader::FreeDLL(const LPVOID lpModule)
{
	const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpModule;
	const auto lpImageNTHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);

	if (HasCallbacks(lpModule))
	{
		const auto lpImageTLSDirectory = (PIMAGE_TLS_DIRECTORY)((DWORD_PTR)lpModule + lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		auto lpCallbackArray = (PIMAGE_TLS_CALLBACK*)lpImageTLSDirectory->AddressOfCallBacks;

		while (*lpCallbackArray != nullptr)
		{
			const auto lpImageCallback = *lpCallbackArray;
			lpImageCallback(lpModule, DLL_PROCESS_DETACH, nullptr);
			lpCallbackArray++;
		}

		printf("[+] TLS callbacks executed (DLL_PROCESS_DETACH).\n");
	}

	const auto main = (dllmain)((DWORD_PTR)lpModule + lpImageNTHeader->OptionalHeader.AddressOfEntryPoint);
	const BOOL result = main((HINSTANCE)lpModule, DLL_PROCESS_DETACH, nullptr);

	if (!result)
	{
		printf("[-] An error is occured when trying to call dllmain with DLL_PROCESS_DETACH !\n");
		return FALSE;
	}

	printf("[+] dllmain have been called (DLL_PROCESS_DETACH).\n");

	const BOOL bFree = VirtualFree(lpModule, 0, MEM_RELEASE);
	if (!bFree)
	{
		printf("[-] An error is occured when trying to free the DLL !\n");
		return FALSE;
	}

	printf("[+] DLL unloaded successfully !\n");

	return TRUE;
}
