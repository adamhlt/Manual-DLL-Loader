#include "ModuleRegistration.hpp"

#include <intrin.h>

#include "Log.hpp"
#include "PeImage.hpp"

namespace MemoryLoader::Detail
{
	namespace
	{
		// Minimal mirror of the undocumented loader structures. Only the fields
		// that are needed here are declared, in the exact order and alignment of
		// the real structures. The list helpers and the string type are redefined
		// locally to stay independent from the SDK headers.
		struct UnicodeString
		{
			USHORT Length;
			USHORT MaximumLength;
			wchar_t* Buffer;
		};

		struct PebLdrData
		{
			ULONG Length;
			BOOLEAN Initialized;
			PVOID SsHandle;
			LIST_ENTRY InLoadOrderModuleList;
			LIST_ENTRY InMemoryOrderModuleList;
			LIST_ENTRY InInitializationOrderModuleList;
		};

		struct Peb
		{
			BYTE Reserved1[2];
			BYTE BeingDebugged;
			BYTE Reserved2[1];
			PVOID Reserved3[2];
			PebLdrData* Ldr;
		};

		struct LdrDataTableEntry
		{
			LIST_ENTRY InLoadOrderLinks;
			LIST_ENTRY InMemoryOrderLinks;
			LIST_ENTRY InInitializationOrderLinks;
			PVOID DllBase;
			PVOID EntryPoint;
			ULONG SizeOfImage;
			UnicodeString FullDllName;
			UnicodeString BaseDllName;
			ULONG Flags;
			USHORT LoadCount;
			USHORT TlsIndex;
			LIST_ENTRY HashLinks;
			ULONG TimeDateStamp;
		};

		// LDRP_* flags used by ntdll.
		constexpr ULONG LdrpImageDll = 0x00000004;
		constexpr ULONG LdrpEntryProcessed = 0x00004000;
		constexpr ULONG LdrpProcessAttachCalled = 0x00008000;

		void InsertTail(LIST_ENTRY* lpHead, LIST_ENTRY* lpEntry) noexcept
		{
			lpEntry->Blink = lpHead->Blink;
			lpEntry->Flink = lpHead;
			lpHead->Blink->Flink = lpEntry;
			lpHead->Blink = lpEntry;
		}

		void RemoveEntry(LIST_ENTRY* lpEntry) noexcept
		{
			lpEntry->Blink->Flink = lpEntry->Flink;
			lpEntry->Flink->Blink = lpEntry->Blink;
			lpEntry->Flink = lpEntry;
			lpEntry->Blink = lpEntry;
		}

		PebLdrData* GetLdrData() noexcept
		{
#ifdef _WIN64
			const auto lpPeb = reinterpret_cast<Peb*>(__readgsqword(0x60));
#else
			const auto lpPeb = reinterpret_cast<Peb*>(__readfsdword(0x30));
#endif
			return lpPeb != nullptr ? lpPeb->Ldr : nullptr;
		}

		const char* BaseNameFromPath(const char* lpPath) noexcept
		{
			const char* lpBase = lpPath;
			for (const char* lpCurrent = lpPath; *lpCurrent != '\0'; ++lpCurrent)
			{
				if (*lpCurrent == '\\' || *lpCurrent == '/')
					lpBase = lpCurrent + 1;
			}
			return lpBase;
		}
	}

	bool RegisterModule(LPVOID lpImage, const char* lpName) noexcept
	{
		if (lpImage == nullptr || lpName == nullptr)
			return false;

		PebLdrData* lpLdr = GetLdrData();
		if (lpLdr == nullptr)
		{
			LogWarning("Unable to reach the PEB loader data.");
			return false;
		}

		const PeHeaders headers = GetHeaders(lpImage);

		const int dWideLength = MultiByteToWideChar(CP_ACP, 0, lpName, -1, nullptr, 0);
		if (dWideLength <= 0)
			return false;

		const SIZE_T dNameBytes = static_cast<SIZE_T>(dWideLength) * sizeof(wchar_t);
		const auto lpNameBuffer = static_cast<wchar_t*>(HeapAlloc(GetProcessHeap(), 0, dNameBytes));
		if (lpNameBuffer == nullptr)
			return false;

		MultiByteToWideChar(CP_ACP, 0, lpName, -1, lpNameBuffer, dWideLength);

		const auto lpEntry = static_cast<LdrDataTableEntry*>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(LdrDataTableEntry)));
		if (lpEntry == nullptr)
		{
			HeapFree(GetProcessHeap(), 0, lpNameBuffer);
			return false;
		}

		const char* lpBaseName = BaseNameFromPath(lpName);
		const SIZE_T dBaseOffset = static_cast<SIZE_T>(lpBaseName - lpName);

		lpEntry->DllBase = lpImage;
		lpEntry->EntryPoint = reinterpret_cast<LPVOID>(AsInteger(lpImage) + headers.lpNtHeaders->OptionalHeader.AddressOfEntryPoint);
		lpEntry->SizeOfImage = headers.lpNtHeaders->OptionalHeader.SizeOfImage;

		lpEntry->FullDllName.Buffer = lpNameBuffer;
		lpEntry->FullDllName.Length = static_cast<USHORT>((dWideLength - 1) * sizeof(wchar_t));
		lpEntry->FullDllName.MaximumLength = static_cast<USHORT>(dNameBytes);

		lpEntry->BaseDllName.Buffer = lpNameBuffer + dBaseOffset;
		lpEntry->BaseDllName.Length = static_cast<USHORT>((dWideLength - 1 - dBaseOffset) * sizeof(wchar_t));
		lpEntry->BaseDllName.MaximumLength = static_cast<USHORT>(dNameBytes - dBaseOffset * sizeof(wchar_t));

		lpEntry->Flags = LdrpImageDll | LdrpEntryProcessed | LdrpProcessAttachCalled;
		lpEntry->LoadCount = 1;
		lpEntry->TlsIndex = 0;

		// InLoadOrder / InMemoryOrder / InInitializationOrder lists all end with
		// the newest module, so append the entry to each of them.
		InsertTail(&lpLdr->InLoadOrderModuleList, &lpEntry->InLoadOrderLinks);
		InsertTail(&lpLdr->InMemoryOrderModuleList, &lpEntry->InMemoryOrderLinks);
		InsertTail(&lpLdr->InInitializationOrderModuleList, &lpEntry->InInitializationOrderLinks);

		LogInfo("Module registered in the PEB as \"%s\".", lpName);
		return true;
	}

	void UnregisterModule(LPVOID lpImage) noexcept
	{
		if (lpImage == nullptr)
			return;

		PebLdrData* lpLdr = GetLdrData();
		if (lpLdr == nullptr)
			return;

		for (LIST_ENTRY* lpLink = lpLdr->InLoadOrderModuleList.Flink; lpLink != &lpLdr->InLoadOrderModuleList; lpLink = lpLink->Flink)
		{
			const auto lpEntry = reinterpret_cast<LdrDataTableEntry*>(lpLink);
			if (lpEntry->DllBase != lpImage)
				continue;

			RemoveEntry(&lpEntry->InLoadOrderLinks);
			RemoveEntry(&lpEntry->InMemoryOrderLinks);
			RemoveEntry(&lpEntry->InInitializationOrderLinks);

			if (lpEntry->FullDllName.Buffer != nullptr)
				HeapFree(GetProcessHeap(), 0, lpEntry->FullDllName.Buffer);
			HeapFree(GetProcessHeap(), 0, lpEntry);

			LogInfo("Module unregistered from the PEB.");
			return;
		}
	}
}
