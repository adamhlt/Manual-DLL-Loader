#ifndef MANUALLOADER_DETAIL_LOG_HPP
#define MANUALLOADER_DETAIL_LOG_HPP

#include "ManualLoader/Loader.hpp"

namespace MemoryLoader
{
	void LogDebug(const char* lpFormat, ...) noexcept;
	void LogInfo(const char* lpFormat, ...) noexcept;
	void LogWarning(const char* lpFormat, ...) noexcept;
	void LogError(const char* lpFormat, ...) noexcept;
}

#endif
