#include "hook.h"

#include <stdio.h>
#include <string.h>
#include <Windows.h>

const unsigned char jmp_opcode = 0xE9;
const unsigned char nop_opcode = 0x90;

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


void hook(int addr, void* hook, int orig_padding) {
	printf("hooking: %08X pointed to %08X\n", addr, reinterpret_cast<int>(hook) - addr - 5);
	char bla = char(1000);
	char vla = static_cast<char>(1000);

	*((unsigned char*)addr) = jmp_opcode;
	*((int*)(addr + 1)) = reinterpret_cast<int>(hook) - addr - 5;
	for (int i = 0; i < orig_padding; i++) {
		*(char*)(addr + 5 + i) = nop_opcode;
	}
}