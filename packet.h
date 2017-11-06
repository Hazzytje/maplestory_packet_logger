#pragma once
#include "packet_data.h"
#include <vector>

class packet {
private:
	std::vector<packet_data*> packet_parts;
public:
	void add_data(packet_data* data);
	void print();
};