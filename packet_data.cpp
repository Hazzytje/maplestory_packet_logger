#include "packet_data.h"

#include <iterator>
#include <algorithm>
#include <cstdio>

packet_data_byte::packet_data_byte(char val) : value(val) {};

void packet_data_byte::print() {
	std::printf("[%02X] ", value);
}

packet_data_short::packet_data_short(short val) : value(val) {};

void packet_data_short::print() {
	std::printf("[%04X] ", value);
}

packet_data_int::packet_data_int(int val) : value(val) {};

void packet_data_int::print() {
	std::printf("[%08X] ", value);
}

packet_data_string::packet_data_string(std::string val) : value(val) {};

void packet_data_string::print() {
	std::printf("[%s] ", value.c_str());
}

packet_data_buffer::packet_data_buffer(unsigned char *data_ptr, int size) {
	std::copy(data_ptr, data_ptr + size, back_inserter(value));
}

void packet_data_buffer::print() {
	std::printf("[buffer of size: %d] ", value.size());
}
