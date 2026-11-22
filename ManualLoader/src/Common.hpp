#ifndef MANUALLOADER_DETAIL_COMMON_HPP
#define MANUALLOADER_DETAIL_COMMON_HPP

#include <Windows.h>

namespace MemoryLoader::Detail
{
	/** Signature of a PE image entry point (DllMain). */
	using DllMainFn = BOOL(WINAPI*)(HINSTANCE hInstance, DWORD dwReason, LPVOID lpReserved);

	/** Relocation entry as described by the PE format (12-bit offset, 4-bit type). */
	struct RelocationEntry
	{
		WORD Offset : 12;
		WORD Type : 4;
	};

	/** Delay-load import descriptor (IMAGE_DELAYLOAD_DESCRIPTOR). */
	struct DelayLoadDescriptor
	{
		DWORD Attributes;
		DWORD DllNameRva;
		DWORD ModuleHandleRva;
		DWORD ImportAddressTableRva;
		DWORD ImportNameTableRva;
		DWORD BoundImportAddressTableRva;
		DWORD UnloadInformationTableRva;
		DWORD TimeDateStamp;
	};
	using PDelayLoadDescriptor = DelayLoadDescriptor*;

	/** Interprets a pointer as an integer so it can be used in address arithmetic. */
	inline DWORD_PTR AsInteger(LPCVOID lpPointer) noexcept
	{
		return reinterpret_cast<DWORD_PTR>(const_cast<LPVOID>(lpPointer));
	}
}

#endif
