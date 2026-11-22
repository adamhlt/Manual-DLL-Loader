#include <cstdio>
#include <cstdlib>

#include "ManualLoader/Loader.hpp"

// Function pointer
using MessageFncPtr = void (*)();

int main()
{
	MemoryLoader::Status status = MemoryLoader::Status::Success;
	LPVOID lpModule = MemoryLoader::LoadDLL("test.dll", &status);
	if (lpModule == nullptr)
	{
		std::printf("[-] Unable to load the DLL (status %d).\n", static_cast<int>(status));
		return -1;
	}

	const auto MessageFnc = reinterpret_cast<MessageFncPtr>(MemoryLoader::GetFunctionAddress(lpModule, "Message"));
	if (MessageFnc == nullptr)
	{
		MemoryLoader::FreeDLL(lpModule);
		return -1;
	}

	MessageFnc();

	const auto MessageFncByOrdinal = reinterpret_cast<MessageFncPtr>(MemoryLoader::GetFunctionAddressByOrdinal(lpModule, 1));
	if (MessageFncByOrdinal != nullptr)
		MessageFncByOrdinal();

	MemoryLoader::FreeDLL(lpModule);

	std::system("PAUSE");

	return 0;
}
