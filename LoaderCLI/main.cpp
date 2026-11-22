#include <cstdio>
#include <cstring>
#include <vector>

#include "ManualLoader/Loader.hpp"

namespace
{
	void PrintUsage(const char* lpProgram)
	{
		std::printf(
			"ManualLoader CLI - manually map a DLL and inspect or call its exports.\n"
			"\n"
			"Usage: %s [options] <path-to-dll> [export]\n"
			"\n"
			"Options:\n"
			"  -l, --list      List the exports (default when no export is given).\n"
			"  -c, --call      Call the given export as void(*)(void).\n"
			"  -v, --verbose   Enable debug logging.\n"
			"  -q, --quiet     Only report errors.\n"
			"  -h, --help      Show this message.\n",
			lpProgram);
	}
}

int main(int argc, char** argv)
{
	const char* lpPath = nullptr;
	const char* lpExport = nullptr;
	bool bList = false;
	bool bCall = false;

	for (int i = 1; i < argc; ++i)
	{
		const char* lpArg = argv[i];

		if (std::strcmp(lpArg, "-h") == 0 || std::strcmp(lpArg, "--help") == 0)
		{
			PrintUsage(argv[0]);
			return 0;
		}
		else if (std::strcmp(lpArg, "-v") == 0 || std::strcmp(lpArg, "--verbose") == 0)
			MemoryLoader::SetLogLevel(MemoryLoader::LogLevel::Debug);
		else if (std::strcmp(lpArg, "-q") == 0 || std::strcmp(lpArg, "--quiet") == 0)
			MemoryLoader::SetLogLevel(MemoryLoader::LogLevel::Error);
		else if (std::strcmp(lpArg, "-l") == 0 || std::strcmp(lpArg, "--list") == 0)
			bList = true;
		else if (std::strcmp(lpArg, "-c") == 0 || std::strcmp(lpArg, "--call") == 0)
			bCall = true;
		else if (lpPath == nullptr)
			lpPath = lpArg;
		else
			lpExport = lpArg;
	}

	if (lpPath == nullptr)
	{
		PrintUsage(argv[0]);
		return 1;
	}

	MemoryLoader::Status status = MemoryLoader::Status::Success;
	const MemoryLoader::Module module = MemoryLoader::Module::FromFile(lpPath, &status);
	if (!module)
	{
		std::printf("[-] Unable to load \"%s\" (status %d).\n", lpPath, static_cast<int>(status));
		return 1;
	}

	if (lpExport == nullptr || bList)
	{
		const std::vector<MemoryLoader::Export> exports = module.GetExports();
		std::printf("[+] %zu export(s):\n", exports.size());
		for (const auto& entry : exports)
		{
			if (entry.lpName != nullptr)
				std::printf("    0x%p  #%-5lu  %s\n", entry.lpAddress, entry.dOrdinal, entry.lpName);
			else
				std::printf("    0x%p  #%-5lu  (ordinal only)\n", entry.lpAddress, entry.dOrdinal);
		}
	}

	if (lpExport != nullptr && !bList)
	{
		using ExportFn = void (*)();

		const auto fn = reinterpret_cast<ExportFn>(module.GetFunction(lpExport));
		if (fn == nullptr)
		{
			std::printf("[-] Export \"%s\" not found.\n", lpExport);
			return 1;
		}

		std::printf("[+] Calling \"%s\" at 0x%p...\n", lpExport, reinterpret_cast<const void*>(fn));
		fn();
	}

	return 0;
}
