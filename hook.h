#pragma once

void* make_hook_page(int hook_addr, int ret_addr, unsigned char* orig_bytes, int orig_byte_size);
void hook(int addr, void* hook, int orig_padding = 0);