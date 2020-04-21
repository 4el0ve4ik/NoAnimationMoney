#include <Windows.h>
#include <process.h>

void Thread(void*) {
	DWORD oldProt;
	VirtualProtect((void*)0x5700F7, 9, PAGE_EXECUTE_READWRITE, &oldProt);
	*reinterpret_cast<unsigned char*>(0x5700F7) = 0xB8;
	memcpy((void*)0x5700FB, (PBYTE)"\x89\x96\xBC\x00\x00\x00", 7);
	VirtualProtect((void*)0x5700F7, 9, oldProt, NULL);
	VirtualProtect((void*)0x570103, 1, PAGE_EXECUTE_READWRITE, &oldProt);
	*reinterpret_cast<unsigned char*>(0x570103) = 0xEB;
	VirtualProtect((void*)0x570103, 1, oldProt, NULL);
}

BOOL APIENTRY DllMain(HMODULE, DWORD  fdwReason, LPVOID) {
	if (fdwReason == DLL_PROCESS_ATTACH)
		_beginthread(Thread, NULL, NULL);

	return TRUE;
}
