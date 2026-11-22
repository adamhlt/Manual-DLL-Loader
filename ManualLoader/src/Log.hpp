#ifndef MANUALLOADER_DETAIL_LOG_HPP
#define MANUALLOADER_DETAIL_LOG_HPP

#include <cstdarg>
#include <cstdio>

namespace MemoryLoader
{
	/** Severity of a log message. */
	enum class LogLevel
	{
		Debug = 0,
		Info,
		Warning,
		Error,
		Silent,
	};

	namespace Detail
	{
		inline LogLevel& LogThreshold() noexcept
		{
			static LogLevel s_level = LogLevel::Info;
			return s_level;
		}

		inline void VLog(LogLevel level, const char* lpFormat, va_list args) noexcept
		{
			if (level < LogThreshold())
				return;

			const char* lpPrefix = "[+] ";
			switch (level)
			{
			case LogLevel::Debug:   lpPrefix = "[*] "; break;
			case LogLevel::Warning: lpPrefix = "[!] "; break;
			case LogLevel::Error:   lpPrefix = "[-] "; break;
			default:                lpPrefix = "[+] "; break;
			}

			std::fputs(lpPrefix, stdout);
			std::vfprintf(stdout, lpFormat, args);
			std::fputc('\n', stdout);
		}
	}

	/** Sets the minimum severity that is printed. */
	inline void SetLogLevel(LogLevel level) noexcept
	{
		Detail::LogThreshold() = level;
	}

	inline void LogDebug(const char* lpFormat, ...) noexcept
	{
		va_list args;
		va_start(args, lpFormat);
		Detail::VLog(LogLevel::Debug, lpFormat, args);
		va_end(args);
	}

	inline void LogInfo(const char* lpFormat, ...) noexcept
	{
		va_list args;
		va_start(args, lpFormat);
		Detail::VLog(LogLevel::Info, lpFormat, args);
		va_end(args);
	}

	inline void LogWarning(const char* lpFormat, ...) noexcept
	{
		va_list args;
		va_start(args, lpFormat);
		Detail::VLog(LogLevel::Warning, lpFormat, args);
		va_end(args);
	}

	inline void LogError(const char* lpFormat, ...) noexcept
	{
		va_list args;
		va_start(args, lpFormat);
		Detail::VLog(LogLevel::Error, lpFormat, args);
		va_end(args);
	}
}

#endif
