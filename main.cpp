#define _CRT_SECURE_NO_WARNINGS

#define extern_c extern "C"
#define dll_export __declspec( dllexport )
#define dll_func extern_c dll_export

#include <iostream>
#include <iosfwd>

#include <windows.h>

const unsigned char jmp_opcode = 0xE9;

const int send_packet_addr = 0x0049637B;
const int encode1_addr = 0x00406549;
const int encode2_addr = 0x00427F74;
const int encode4_addr = 0x004065A6;
const int encode_buffer_addr = 0x0046C00C;
const int encode_str_addr = 0x0046F3CF;

dll_func void encode1() {
	printf("byte\n");
}

dll_func void encode2() {
	printf("short\n");
}

dll_func void encode4() {
	printf("int\n");
}

dll_func void encode_string() {
	printf("string\n");
}

dll_func void encode_buffer() {
	printf("buffer\n");
}

dll_func void packet_sent() {
	printf("packet sent\n");
}

void open_console() {
	AllocConsole();

	freopen("conin$", "r", stdin);
	freopen("conout$", "w", stdout);
	freopen("conout$", "w", stderr);

	printf("Debugging Window:\n");
}

void hook(int addr, void* hook) {
	printf("hooking: %08X pointed to %08X\n", addr, reinterpret_cast<int>(hook) - addr - 5);
	char bla = char(1000);
	char vla = static_cast<char>(1000);

	*((unsigned char*)addr) = jmp_opcode;
	*((int*)(addr + 1)) = reinterpret_cast<int>(hook) - addr - 5;
}

bool launchDebugger() {
	// Get System directory, typically c:\windows\system32
	std::wstring systemDir(MAX_PATH + 1, '\0');
	UINT nChars = GetSystemDirectoryW(&systemDir[0], systemDir.length());
	if (nChars == 0) return false; // failed to get system directory
	systemDir.resize(nChars);

	// Get process ID and create the command line
	DWORD pid = GetCurrentProcessId();

	WCHAR cmdline[1000] = {};
	wsprintfW(cmdline, L"%s\\vsjitdebugger.exe -p %d", systemDir.c_str(), pid);
	
	std::wstring cmdLine = cmdline;

	// Start debugger process
	STARTUPINFOW si;
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);

	PROCESS_INFORMATION pi;
	ZeroMemory(&pi, sizeof(pi));

	if (!CreateProcessW(NULL, &cmdLine[0], NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) return false;

	// Close debugger process handles to eliminate resource leak
	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);

	// Wait for the debugger to attach
	while (!IsDebuggerPresent()) Sleep(100);
	return true;
}

void* make_hook_page(int hook_addr, int ret_addr, unsigned char writelen) {
	unsigned char shellcode[] = {
		0x60, //pushad
		0xE8, 0x00, 0x00, 0x00, 0x00, //call
		0x61, //popad
		0x56, //push esi
		0x8B, 0xF1, //mov esi, ecx
		0x6A, writelen, //push 1
		0x68, 0x00, 0x00, 0x00, 0x00, //push 
		0xC3 //ret
	};
	printf("allocating memory...\n");
	unsigned char* shellcode_page = static_cast<unsigned char*>(VirtualAlloc(nullptr, 1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
	printf("allocated memory, at %p, now copying shellcode into buffer\n", shellcode_page);
	memcpy(shellcode_page, shellcode, sizeof(shellcode));

	int relative_hook_addr = hook_addr - reinterpret_cast<int>(shellcode_page) - 6;
	memcpy(shellcode_page + 2, &relative_hook_addr, 4); //copy hook addr over 0x00 bytes
	memcpy(shellcode_page + 13, &ret_addr, 4); //copy ret addr over 0x00 bytes

	printf("copied the addresses into the shellcode\n");
	return shellcode_page;
}

BOOL WINAPI DllMain(_In_ HINSTANCE hinstDLL, _In_ DWORD fdwReason, _In_ LPVOID lpvReserved) {
	if (fdwReason != DLL_PROCESS_ATTACH) { 
		return TRUE;
	}

	//launchDebugger();

	open_console();

	HMODULE dlladdress = GetModuleHandle("packet_logger.dll");
	int encode1_dll_addr = reinterpret_cast<int>(GetProcAddress(dlladdress, "encode1"));
	int encode2_dll_addr = reinterpret_cast<int>(GetProcAddress(dlladdress, "encode2"));
	int encode4_dll_addr = reinterpret_cast<int>(GetProcAddress(dlladdress, "encode4"));
	int encode_string_dll_addr = reinterpret_cast<int>(GetProcAddress(dlladdress, "encode_string"));
	int encode_buffer_dll_addr = reinterpret_cast<int>(GetProcAddress(dlladdress, "encode_buffer"));
	int packet_sent_dll_addr =  reinterpret_cast<int>(GetProcAddress(dlladdress, "packet_sent"));

	printf("function baseaddr is at %p\n", dlladdress);
	printf("function encode1 is at %p\n", (void*)encode1_dll_addr);
	printf("function encode2 is at %p\n", (void*)encode2_dll_addr);
	printf("function encode4 is at %p\n", (void*)encode4_dll_addr);
	printf("function encodestr is at %p\n", (void*)encode_string_dll_addr);
	printf("function encodebuf is at %p\n", (void*)encode_buffer_dll_addr);
	printf("function sent is at %p\n", (void*)packet_sent_dll_addr);

	hook(encode1_addr, make_hook_page(encode1_dll_addr, encode1_addr + 5, 1));
	hook(encode2_addr, make_hook_page(encode2_dll_addr, encode2_addr + 5, 2));
	hook(encode4_addr, make_hook_page(encode4_dll_addr, encode4_addr + 5, 4));

	return TRUE;
}