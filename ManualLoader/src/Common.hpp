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

	/** Interprets a pointer as an integer so it can be used in address arithmetic. */
	inline DWORD_PTR AsInteger(LPCVOID lpPointer) noexcept
	{
		return reinterpret_cast<DWORD_PTR>(const_cast<LPVOID>(lpPointer));
	}
}

#endif
