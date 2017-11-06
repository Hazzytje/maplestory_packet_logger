#pragma once

#include <string>
#include <vector>

class packet_data {
public:
	virtual void print() = 0;
};

class packet_data_byte : public packet_data {
private:
	char value;
public:
	packet_data_byte(char val);
	void print() override;
};

class packet_data_short : public packet_data {
private:
	short value;
public:
	packet_data_short(short val);
	void print() override;
};

class packet_data_int : public packet_data {
private:
	int value;
public:
	packet_data_int(int val);
	void print() override;
};

class packet_data_string : public packet_data {
private:
	std::string value;
public:
	packet_data_string(std::string val);
	void print() override;
};

class packet_data_buffer : public packet_data {
private:
	std::vector<unsigned char> value;
public:
	packet_data_buffer(unsigned char *data_ptr, int size);
	void print() override;
};