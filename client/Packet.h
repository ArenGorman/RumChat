#include <string>
#include <vector>

#pragma once
using namespace std;

enum PacketTypeEnum {
	ID,
	MSGT,
	MSGIN,
	USERS,
	CHANNELS,
	JOIN,
	LEAVE,
	INVALID,
};

class Packet
{
public:
	Packet(const char * rawData);
	Packet(PacketTypeEnum command, string farg, string sarg, string targ);
	~Packet();
	PacketTypeEnum Command;
	string FirstArgument;
	string SecondArgument;
	string ThirdArgument;
	string Encode();
private:
	static void Decode(const char * rawData, PacketTypeEnum &commandRef, string &firstArgRef, string &secondArgRef, string &thirdArgRef);
};

