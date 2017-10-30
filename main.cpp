#define _CRT_SECURE_NO_WARNINGS

#define extern_c extern "C"
#define dll_export __declspec( dllexport )
#define dll_func extern_c dll_export

#include <iostream>
#include <iosfwd>

#include <windows.h>

const unsigned char jmp_opcode = 0xE9;
const unsigned char nop_opcode = 0x90;

const int send_packet_addr = 0x0049637B;
const int encode1_addr = 0x00406549;
const int encode2_addr = 0x00427F74;
const int encode4_addr = 0x004065A6;
const int encode_buffer_addr = 0x0046C00C;
const int encode_str_addr = 0x0046F3CF;

dll_func void encode1() {
	int p = 3;
	void* ptr = &p + 14;
	unsigned int decval = *(unsigned int*)ptr;
	printf("byte: %02X, %d ", decval, decval);
}

dll_func void encode2() {
	int p = 3;
	void* ptr = &p + 14;
	unsigned int decval = *(unsigned int*)ptr;
	printf("short: %04X, %d ", decval, decval);
}

dll_func void encode4() {
	int p = 3;
	void* ptr = &p + 14;
	int decval = *(int*)ptr;
	printf("int: %08X, %d ", decval, decval);
}

dll_func void encode_string() {
	int p = 3;
	void* ptr = &p + 14;
	char* strval = *(char**)ptr;
	printf("str at %p: [%s] ", strval, strval);
}

dll_func void encode_buffer() {
	int p = 3;
	void* ptrlen = &p + 15;
	void* ptrbuff = &p + 14;
	int bufflen = *(int*)ptrlen;
	unsigned char* buffer = *(unsigned char**)ptrbuff;

	printf("buffer size %d ", bufflen);
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

void hook(int addr, void* hook, int orig_padding = 0) {
	printf("hooking: %08X pointed to %08X\n", addr, reinterpret_cast<int>(hook) - addr - 5);
	char bla = char(1000);
	char vla = static_cast<char>(1000);

	*((unsigned char*)addr) = jmp_opcode;
	*((int*)(addr + 1)) = reinterpret_cast<int>(hook) - addr - 5;
	for (int i = 0; i < orig_padding; i++) {
		*(char*)(addr + 5 + i) = nop_opcode;
	}
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

void* make_hook_page(int hook_addr, int ret_addr, unsigned char* orig_bytes, int orig_byte_size) {
	unsigned char* shellcode = static_cast<unsigned char*>(VirtualAlloc(nullptr, 1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
	printf("allocated memory at %p, now copying shellcode into buffer\n", shellcode);

	int relative_hook_addr = hook_addr - reinterpret_cast<int>(shellcode) - 6;

	int i = 0;
	shellcode[i++] = 0x60; //pushad
	shellcode[i++] = 0xE8; //call
	*reinterpret_cast<int*>(shellcode + i) = relative_hook_addr; i += 4; //call addr
	shellcode[i++] = 0x61; //popad
	memcpy(shellcode + i, orig_bytes, orig_byte_size); i += orig_byte_size; //original bytes
	shellcode[i++] = 0x68; //push
	*reinterpret_cast<int*>(shellcode + i) = ret_addr; i += 4; //ret addr
	shellcode[i++] = 0xC3; //ret
	
	return shellcode;
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

	unsigned char encode_orig[] = {0x56, 0x8B, 0xF1, 0x6A, 0x01};
	hook(encode1_addr, make_hook_page(encode1_dll_addr, encode1_addr + 5, encode_orig, sizeof(encode_orig)));
	encode_orig[4] = 2;
	hook(encode2_addr, make_hook_page(encode2_dll_addr, encode2_addr + 5, encode_orig, sizeof(encode_orig)));
	encode_orig[4] = 4;
	hook(encode4_addr, make_hook_page(encode4_dll_addr, encode4_addr + 5, encode_orig, sizeof(encode_orig)));

	unsigned char buffer_orig[] = {0x56, 0x57, 0x8B, 0x7C, 0x24, 0x10};
	hook(encode_buffer_addr, make_hook_page(encode_buffer_dll_addr, encode_buffer_addr + 5, buffer_orig, sizeof(buffer_orig)), 1);

	unsigned char str_orig[] = {0xB8, 0x00, 0xE5, 0xA7, 0x00};
	hook(encode_str_addr, make_hook_page(encode_string_dll_addr, encode_str_addr + 5, str_orig, sizeof(str_orig)));

	unsigned char send_orig[] = {0xB8, 0x6C, 0x12, 0xA8, 0x00};
	hook(send_packet_addr, make_hook_page(packet_sent_dll_addr, send_packet_addr + 5, send_orig, sizeof(send_orig)));

	return TRUE;
}