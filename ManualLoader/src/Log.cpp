#include "Log.hpp"

#include <cstdarg>
#include <cstdio>

namespace
{
	MemoryLoader::LogLevel g_threshold = MemoryLoader::LogLevel::Info;
	MemoryLoader::LogCallback g_callback = nullptr;

	const char* PrefixFor(MemoryLoader::LogLevel level) noexcept
	{
		switch (level)
		{
		case MemoryLoader::LogLevel::Debug:   return "[*] ";
		case MemoryLoader::LogLevel::Warning: return "[!] ";
		case MemoryLoader::LogLevel::Error:   return "[-] ";
		default:                              return "[+] ";
		}
	}
}

namespace MemoryLoader
{
	void SetLogLevel(LogLevel level) noexcept
	{
		g_threshold = level;
	}

	void SetLogCallback(LogCallback lpCallback) noexcept
	{
		g_callback = lpCallback;
	}

	namespace Detail
	{
		void VLog(LogLevel level, const char* lpFormat, va_list args) noexcept
		{
			if (level < g_threshold)
				return;

			char buffer[1024];
			if (std::vsnprintf(buffer, sizeof(buffer), lpFormat, args) < 0)
				return;

			if (g_callback != nullptr)
			{
				g_callback(level, buffer);
				return;
			}

			std::printf("%s%s\n", PrefixFor(level), buffer);
		}
	}

	void LogDebug(const char* lpFormat, ...) noexcept
	{
		va_list args;
		va_start(args, lpFormat);
		Detail::VLog(LogLevel::Debug, lpFormat, args);
		va_end(args);
	}

	void LogInfo(const char* lpFormat, ...) noexcept
	{
		va_list args;
		va_start(args, lpFormat);
		Detail::VLog(LogLevel::Info, lpFormat, args);
		va_end(args);
	}

	void LogWarning(const char* lpFormat, ...) noexcept
	{
		va_list args;
		va_start(args, lpFormat);
		Detail::VLog(LogLevel::Warning, lpFormat, args);
		va_end(args);
	}

	void LogError(const char* lpFormat, ...) noexcept
	{
		va_list args;
		va_start(args, lpFormat);
		Detail::VLog(LogLevel::Error, lpFormat, args);
		va_end(args);
	}
}
