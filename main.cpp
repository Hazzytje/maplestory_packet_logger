#define _CRT_SECURE_NO_WARNINGS

#define extern_c extern "C"
#define dll_export __declspec( dllexport )
#define dll_func extern_c dll_export

#include <iostream>
#include <algorithm>
#include <iosfwd>
#include <map>

#include <windows.h>
#include "hook.h"
#include "packet.h"

const int send_packet_addr = 0x0049637B;
const int encode1_addr = 0x00406549;
const int encode2_addr = 0x00427F74;
const int encode4_addr = 0x004065A6;
const int encode_buffer_addr = 0x0046C00C;
const int encode_str_addr = 0x0046F3CF;

std::map<void*, packet> active_packets;

void print_stack(int* start) {
	for (int i = 0; i < 15; i++) {
		printf("%p\n", *(start + i));
	}
	printf("\n");
}

dll_func void encode1() {
	int p = 3;

	void* val_ptr = &p + 14;
	unsigned int decval = *(unsigned int*)val_ptr;

	void* this_ptr = &p + 5;
	void* this_val = *(void**)this_ptr;

	active_packets[this_val].add_data(new packet_data_byte(decval));
	//printf("byte: %02X, %d ", decval, decval);
}

dll_func void encode2() {
	int p = 3;
	void* ptr = &p + 14;
	unsigned int decval = *(unsigned int*)ptr;

	void* this_ptr = &p + 5;
	void* this_val = *(void**)this_ptr;

	active_packets[this_val].add_data(new packet_data_short(decval));
	//printf("short: %04X, %d ", decval, decval);
}

dll_func void encode4() {
	int p = 3;
	void* ptr = &p + 14;
	int decval = *(int*)ptr;

	void* this_ptr = &p + 5;
	void* this_val = *(void**)this_ptr;

	active_packets[this_val].add_data(new packet_data_int(decval));
	//printf("int: %08X, %d ", decval, decval);
}

dll_func void encode_string() {
	int p = 3;
	void* ptr = &p + 14;
	char* strval = *(char**)ptr;

	void* this_ptr = &p + 5;
	void* this_val = *(void**)this_ptr;

	active_packets[this_val].add_data(new packet_data_string(strval));
	//printf("str at %p: [%s] ", strval, strval);
}

dll_func void encode_buffer() {
	int p = 3;
	void* ptrlen = &p + 15;
	void* ptrbuff = &p + 14;
	int bufflen = *(int*)ptrlen;
	unsigned char* buffer = *(unsigned char**)ptrbuff;

	void* this_ptr = &p + 5;
	void* this_val = *(void**)this_ptr;

	active_packets[this_val].add_data(new packet_data_buffer(buffer, bufflen));
	//printf("buffer size %d ", bufflen);
}

dll_func void packet_sent() {
	int p = 3;

	void* this_ptr = &p + 5;
	void* this_val = *(void**)this_ptr;

	printf("packet_sent\n");

	active_packets.at(this_val).print();
	active_packets.erase(active_packets.find(this_val));
	/*
	for (int i = 0; i < 20; i++) {
		void* packet_ptr = &p + 3 + i;
		void* packet_val = *(void**)this_ptr;

		if (active_packets.find(packet_val) != active_packets.end()) {
			active_packets.at(this_val).print();
			active_packets.erase(active_packets.find(this_val));

			printf("index at p+%d", 3 + i);
			break;
		}
	}
	*/
	
	printf("packet sent\n");
}

void open_console() {
	AllocConsole();

	freopen("conin$", "r", stdin);
	freopen("conout$", "w", stdout);
	freopen("conout$", "w", stderr);

	printf("Debugging Window:\n");
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