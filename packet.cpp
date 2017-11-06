#include "packet.h"
#include <cstdio>

void packet::add_data(packet_data* data) {
	packet_parts.push_back(data);
}

void packet::print() {
	for (auto part : packet_parts) {
		part->print();
	}
	std::printf("\n");
}