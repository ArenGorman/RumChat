#include "Packet.h"
#include <sstream>

Packet::Packet(const char * rawData)
{
	this->Command = PacketTypeEnum::INVALID;
	this->FirstArgument = "";
	this->SecondArgument = "";
	this->ThirdArgument = "";
	Packet::Decode(rawData, this->Command, this->FirstArgument, this->SecondArgument, this->ThirdArgument);
}

Packet::Packet(PacketTypeEnum command, string farg, string sarg, string targ) {
	this->Command = command;
	this->FirstArgument = farg;
	this->SecondArgument = sarg;
	this->ThirdArgument = targ;
}

Packet::~Packet()
{
}

string PacketTypeEnumNames[8] = { "ID", "MSG", "MSGIN", "USERS", "CHANNELS", "JOIN", "LEAVE", "INVALID" };

string Packet::Encode() {
	string tmp = this->FirstArgument;
	if (!this->SecondArgument.empty()) {
		tmp += "|" + this->SecondArgument;
	}
	if (!this->ThirdArgument.empty()) {
		tmp += "|" + this->ThirdArgument;
	}
	tmp = PacketTypeEnumNames[this->Command] + "#" + tmp + "\n";
	return tmp;
}

void split(const string& s, char c, vector<string>& v) {
	string::size_type i = 0;
	string::size_type j = s.find(c);

	while (j != string::npos) {
		v.push_back(s.substr(i, j - i));
		i = ++j;
		j = s.find(c, j);

		if (j == string::npos) {
			v.push_back(s.substr(i, s.length()));
		}
	}

	if (v.size() == 0) {
		v.push_back(s);
	}
}

void Packet::Decode(const char * rawData, PacketTypeEnum &commandRef, string &firstArgRef, string &secondArgRef, string &thirdArgRef) {
	vector<string> rawparts;
	split(rawData, '\n', rawparts);
	if (rawparts.size() < 1) {
		return;
	}

	vector<string> parts;
	split(rawparts[0], '#', parts);

	if (parts.size() < 1) {
		return;
	}

	int j = size(PacketTypeEnumNames);
	for (int i = 0; i < j; i++)
	{
		if (parts[0] == PacketTypeEnumNames[i]) {
			commandRef = (PacketTypeEnum)i;
			break;
		}
	}

	if (parts.size() < 2) {
		return;
	}

	vector<string> args;
	split(parts[1], '|', args);

	if (args.size() > 0) {
		firstArgRef = args[0];
		if (args.size() > 1) {
			secondArgRef = args[1];
			if (args.size() > 2) {
				thirdArgRef = args[2];
			}
		}
	}
}
