#include "Exceptions.hpp"

#include "Log.hpp"
#include "PeImage.hpp"

namespace MemoryLoader::Detail
{
#ifdef _WIN64
	namespace
	{
		/** Returns the RUNTIME_FUNCTION array of an image, or nullptr when there is none. */
		PRUNTIME_FUNCTION GetExceptionTable(LPVOID lpImage, DWORD* lpCount) noexcept
		{
			*lpCount = 0;

			const IMAGE_DATA_DIRECTORY directory = GetDataDirectory(lpImage, IMAGE_DIRECTORY_ENTRY_EXCEPTION);
			if (directory.VirtualAddress == 0 || directory.Size == 0)
				return nullptr;

			*lpCount = directory.Size / sizeof(RUNTIME_FUNCTION);
			return reinterpret_cast<PRUNTIME_FUNCTION>(AsInteger(lpImage) + directory.VirtualAddress);
		}
	}
#endif

	bool RegisterExceptionTable(LPVOID lpImage) noexcept
	{
		if (lpImage == nullptr)
			return false;

#ifdef _WIN64
		DWORD dCount = 0;
		PRUNTIME_FUNCTION lpTable = GetExceptionTable(lpImage, &dCount);
		if (lpTable == nullptr || dCount == 0)
		{
			LogDebug("The image has no exception directory.");
			return true;
		}

		if (!RtlAddFunctionTable(lpTable, dCount, static_cast<DWORD64>(AsInteger(lpImage))))
		{
			LogError("Unable to register the exception table.");
			return false;
		}

		LogInfo("Exception table registered (%lu entries).", dCount);
#else
		LogDebug("Exception table registration is not required on this architecture.");
#endif

		return true;
	}

	void UnregisterExceptionTable(LPVOID lpImage) noexcept
	{
		if (lpImage == nullptr)
			return;

#ifdef _WIN64
		DWORD dCount = 0;
		PRUNTIME_FUNCTION lpTable = GetExceptionTable(lpImage, &dCount);
		if (lpTable != nullptr && dCount != 0)
		{
			RtlDeleteFunctionTable(lpTable);
			LogInfo("Exception table unregistered.");
		}
#endif
	}
}
