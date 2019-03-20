#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>
#include <string>
#include <map>
#include <ctime>
#include "Packet.h"

#pragma comment (lib, "Ws2_32.lib")


#define DEFAULT_BUFLEN 512
#define DEFAULT_PORT "27015"
#define DEFAULT_USER "anonimous"

struct IoOperationData {
	OVERLAPPED overlapped;
	WSABUF wsaBuf;
	CHAR buffer[DEFAULT_BUFLEN];
	DWORD bytesSent;
	DWORD bytesRecv;
};

struct ConnectionData {
	SOCKET socket;
	Packet *lastPacket;
	string userName;
};

struct ClientData {
	IoOperationData *ioData;
	ConnectionData *cData;
};


DWORD WINAPI ServerWorkerThread(LPVOID pCompletionPort);
void HandleClientState(ConnectionData *conData, IoOperationData *pIoData);
bool SendChatMessage(string from, string to, string text, string &error);

void prntWT(const char * str) {
	time_t current_time;
	struct tm time_info;
	char timeString[9];

	time(&current_time);
	localtime_s(&time_info, &current_time);

	strftime(timeString, sizeof(timeString), "%H:%M:%S", &time_info);
	printf_s("[%s] %s", timeString, str);
}

int __cdecl main(void)
{
	int error;

	WSADATA wsaData;
	error = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (error != 0) {
		printf("WSAStartup failed with error: %d\n", error);
		return EXIT_FAILURE;
	}

	// Создаем порт завершения
	HANDLE hCompletionPort = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
	if (hCompletionPort == NULL) {
		printf("CreateIoCompletionPort failed with error %d\n", GetLastError());
		WSACleanup();
		return EXIT_FAILURE;
	}

	// Определяеи количество процессоров в системе
	SYSTEM_INFO systemInfo;
	GetSystemInfo(&systemInfo);

	// Создаем рабочие потоки в зависимости от количества процессоров, по два потока на процессор
	for (int i = 0; i < (int)systemInfo.dwNumberOfProcessors * 2; ++i) {
		// Создаем поток и передаем в него порт завершения
		DWORD threadId;
		HANDLE hThread = CreateThread(NULL, 0, ServerWorkerThread, hCompletionPort, 0, &threadId);
		if (hThread == NULL) {
			printf("CreateThread() failed with error %d\n", GetLastError());
			WSACleanup();
			CloseHandle(hCompletionPort);
			return EXIT_FAILURE;
		}

		// Закрываем дескриптор потока, поток при этом не завершается
		CloseHandle(hThread);
	}

	struct addrinfo hints;
	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = AI_PASSIVE;

	// Преобразуем адрес и номер порта
	struct addrinfo *localAddr = NULL;
	error = getaddrinfo(NULL, DEFAULT_PORT, &hints, &localAddr);
	if (error != 0) {
		printf("getaddrinfo failed with error: %d\n", error);
		WSACleanup();
		return EXIT_FAILURE;
	}

	SOCKET listenSocket = WSASocketW(localAddr->ai_family, localAddr->ai_socktype, 0, NULL, 0, WSA_FLAG_OVERLAPPED);
	if (listenSocket == INVALID_SOCKET) {
		printf("socket failed with error: %ld\n", WSAGetLastError());
		freeaddrinfo(localAddr);
		WSACleanup();
		return EXIT_FAILURE;
	}

	// Привязываем сокет TCP к адресу и ждем подключения
	error = bind(listenSocket, localAddr->ai_addr, (int)localAddr->ai_addrlen);
	if (error == SOCKET_ERROR) {
		printf("bind failed with error: %d\n", WSAGetLastError());
		freeaddrinfo(localAddr);
		closesocket(listenSocket);
		WSACleanup();
		return EXIT_FAILURE;
	}

	freeaddrinfo(localAddr);

	error = listen(listenSocket, SOMAXCONN);
	if (error == SOCKET_ERROR) {
		printf("listen failed with error: %d\n", WSAGetLastError());
		closesocket(listenSocket);
		WSACleanup();
		return EXIT_FAILURE;
	}
	printf("Server listen port: %s\n", DEFAULT_PORT);

	// Принимаем соединения и связывкем их с портом завершения
	for ( ; ; ) {
		SOCKET clientSocket = WSAAccept(listenSocket, NULL, NULL, NULL, 0);
		if (clientSocket == SOCKET_ERROR) {
			printf("WSAAccept failed with error %d\n", WSAGetLastError());
			return EXIT_FAILURE;
		}

		ConnectionData *pConnData = new ConnectionData;
		pConnData->socket = clientSocket;
		pConnData->lastPacket = NULL;
		//TODO: add unique id
		pConnData->userName = DEFAULT_USER;
		printf("New client connected: %s\n", pConnData->userName.c_str());
		// Связываем клиентский сокет с портом завершения
		if (CreateIoCompletionPort((HANDLE)clientSocket, hCompletionPort, (ULONG_PTR)pConnData, 0) == NULL) {
			printf("CreateIoCompletionPort failed with error %d\n", GetLastError());
			return EXIT_FAILURE;
		}

		//  Создаем структуру для операций ввода-вывода и запускаем обработку
		IoOperationData *pIoData = new IoOperationData;
		ZeroMemory(&(pIoData->overlapped), sizeof(OVERLAPPED));
		pIoData->bytesSent = 0;
		pIoData->bytesRecv = 0;
		pIoData->wsaBuf.len = DEFAULT_BUFLEN;
		pIoData->wsaBuf.buf = pIoData->buffer;

		DWORD flags = 0;
		DWORD bytesRecv;
		if (WSARecv(clientSocket, &(pIoData->wsaBuf), 1, &bytesRecv, &flags, &(pIoData->overlapped), NULL) == SOCKET_ERROR) {
			if (WSAGetLastError() != ERROR_IO_PENDING) {
				printf("WSARecv failed with error %d\n", WSAGetLastError());
				return EXIT_FAILURE;
			}
		}
	}

}


DWORD WINAPI ServerWorkerThread(LPVOID pCompletionPort)
{
	HANDLE hCompletionPort = (HANDLE)pCompletionPort;

	for ( ; ; ) {
		DWORD bytesTransferred;
		ConnectionData *pConnectionData;
		IoOperationData *pIoData;
		if (GetQueuedCompletionStatus(hCompletionPort, &bytesTransferred,
			(PULONG_PTR)&pConnectionData, (LPOVERLAPPED *)&pIoData, INFINITE) == 0) {
			if (GetLastError() == 64) {
				printf_s("ERROR_NETNAME_DELETED 64 (0x40) - Client disconnected\n");
			}
			else
			{
				printf_s("GetQueuedCompletionStatus() failed with error %d\n", GetLastError());
			}
			return 0;
		}

		// Проверим, не было ли проблем с сокетом и не было ли закрыто соединение
		if (bytesTransferred == 0) {
			printf_s("Client disconnected: %s\n", pConnectionData->userName.c_str());
			closesocket(pConnectionData->socket);
			delete pConnectionData;
			delete pIoData;
			continue;
		}

		// Если bytesRecv равно 0, то мы начали принимать данные от клиента
		// с завершением вызова WSARecv()
		if (pIoData->bytesRecv == 0) {
			pIoData->bytesRecv = bytesTransferred;

			string rawPacket = string(pIoData->wsaBuf.buf, (size_t)pIoData->bytesRecv);
			printf_s("<in(%s) %s", pConnectionData->userName.c_str(), rawPacket.c_str());
			Packet * recvPacket = new Packet(pIoData->wsaBuf.buf);
			if (recvPacket->Command != PacketTypeEnum::INVALID) {
				//HandlePacket
				pConnectionData->lastPacket = recvPacket;
				HandleClientState(pConnectionData, pIoData);
			}
			pIoData->bytesSent = 0;
		} else {
			pIoData->bytesSent += bytesTransferred;
		}

		if (pIoData->bytesRecv > pIoData->bytesSent) {
			DWORD bytesSent;
			// Посылаем очередно запрос на ввод-вывод WSASend()
			// Так как WSASend() может отправить не все данные, то мы отправляем
			// оставшиеся данные из буфера пока не будут отправлены все
			ZeroMemory(&(pIoData->overlapped), sizeof(OVERLAPPED));
			pIoData->wsaBuf.buf = pIoData->buffer + pIoData->bytesSent;
			pIoData->wsaBuf.len = pIoData->bytesRecv - pIoData->bytesSent;
			if (WSASend(pConnectionData->socket, &(pIoData->wsaBuf), 1, &bytesSent, 0, &(pIoData->overlapped), NULL) == SOCKET_ERROR) {
				if (WSAGetLastError() != ERROR_IO_PENDING) {
					printf_s("WSASend failed with error %d\n", WSAGetLastError());
					return 0;
				}
			}
		} else {
			DWORD bytesRecv;
			pIoData->bytesRecv = 0;
			// Когда все данные отправлены, посылаем запрос ввода-вывода на чтение WSARecv()
			DWORD flags = 0;
			ZeroMemory(&(pIoData->overlapped), sizeof(OVERLAPPED));
			pIoData->wsaBuf.len = DEFAULT_BUFLEN;
			pIoData->wsaBuf.buf = pIoData->buffer;
			if (WSARecv(pConnectionData->socket, &(pIoData->wsaBuf), 1, &bytesRecv, &flags, &(pIoData->overlapped), NULL) == SOCKET_ERROR) {
				if (WSAGetLastError() != ERROR_IO_PENDING) {
					printf_s("WSARecv failed with error %d\n", WSAGetLastError());
					return 0;
				}
			}
		}
	}
}

map<string, ClientData*> UsersList;
map<string, vector<string>> ChannelsToUsersTable;

vector<string> GetUsersList() {
	vector<string> v;
	v.reserve(UsersList.size());
	for (auto const &imap : UsersList)
		v.push_back(imap.first);
	return v;
}

vector<string> GetChannels() {
	vector<string> v;
	v.reserve(ChannelsToUsersTable.size());
	for (auto const &imap : ChannelsToUsersTable)
		v.push_back(imap.first);
	return v;
}

vector<string> GetUsersListFromChannel(string channelName) {
	if (ChannelsToUsersTable.count(channelName) != 0) {
		return ChannelsToUsersTable[channelName];
	}
	return vector<string>{"#-404"};
}

bool JoinUserToChannel(string userName, string channelName, bool &created) {
	created = false;
	if (ChannelsToUsersTable.count(channelName) == 0) {
		created = true;
		ChannelsToUsersTable[channelName] = vector<string>();
	}

	vector<string> &v = ChannelsToUsersTable[channelName];
	if (find(v.begin(), v.end(), userName) != v.end()) {
		return false;
	}
	v.push_back(userName);
	if (!created) {
		string t;
		SendChatMessage("", "@" + channelName, userName + " join to channel", t);
	}
	return true;
}

bool LeaveUserFromChannel(string userName, string channelName, bool &deleted) {
	deleted = false;
	if (ChannelsToUsersTable.count(channelName) == 0) {
		return false;
	}
	vector<string> &v = ChannelsToUsersTable[channelName];
	vector<string>::iterator it = find(v.begin(), v.end(), userName);
	if (it == v.end()) {
		return false;
	}
	v.erase(it, it + 1);

	if (v.size() == 0 && channelName != "global") {
		deleted = true;
		ChannelsToUsersTable.erase(channelName);
	}
	if (!deleted) {
		string t;
		SendChatMessage("", "@" + channelName, userName + " left channel", t);
	}
	return true;
}

string vector_to_string(vector<string> v)
{
	string res = "";
	for (const auto &s : v) res += s + " ";
	return res;
}

bool InternalSendMessage(string from, string to, string channel, string text, string &error) {

	WSABUF wsaBuf;
	char buffer[DEFAULT_BUFLEN];
	DWORD bytesSent = 0;
	DWORD bytesLen;

	Packet *newPacket = new Packet(PacketTypeEnum::MSGIN, from, text, channel);
	string encode = newPacket->Encode();
	strncpy_s(buffer, encode.c_str(), 512);
	bytesLen = encode.length();
	printf_s("out(%s)> %s", to.c_str(), buffer);

	wsaBuf.buf = buffer + bytesSent;
	wsaBuf.len = bytesLen - bytesSent;

	if (WSASend(UsersList[to]->cData->socket, &(wsaBuf), 1, &bytesSent, 0, NULL, NULL) == SOCKET_ERROR) {
		if (WSAGetLastError() != ERROR_IO_PENDING) {
			printf_s("WSASend failed with error %d\n", WSAGetLastError());
			error = "Network error";
			return false;
		}
	}
	return true;
}

bool SendChatMessage(string from, string to, string text, string &error) {
	error = "";
	if (to.rfind("@", 0) != 0) {
		//Is direct message to user
		if (UsersList.count(to) == 0) {
			error = "Reciever not found";
			return false;
		}
		return InternalSendMessage(from, to, "", text, error);
	}

	//Is message to channel
	to.erase(0, 1);
	vector<string> v = GetUsersListFromChannel(to);
	if (!v.empty() && v[0] == "#-404") {
		error = "Channel not found";
		return false;
	}
	string t;
	for (string& usrName : v) {
		if (usrName == from) {
			continue;
		}
		InternalSendMessage(from, usrName, to, text, t);
	}
	return true;
}

void HandleClientState(ConnectionData *conData, IoOperationData *pIoData) {
	SOCKET socket = conData->socket;
	Packet *packet = conData->lastPacket;

	Packet *newPacket = NULL;
	string encode = "";
	string s; 
	vector<string> v;
	bool flag;
	ClientData *tclData;

	PacketTypeEnum type = PacketTypeEnum::INVALID;
	string status = "404";
	string res = "Wrong Command";
	string info = "";

	switch (packet->Command)
	{
	case PacketTypeEnum::ID:
		type = PacketTypeEnum::ID;

		if (conData->userName != DEFAULT_USER) {
			status = "REJECT";
			res = "REJECT";
			info = "Already sign in.";
			break;
		}
		
		if (packet->FirstArgument == "") {
			status = "EMPTY";
			res = "EMPTY";
			info = "Username can't be an empty string";
			break;
		}

		if (UsersList.count(packet->FirstArgument) != 0 || packet->FirstArgument == DEFAULT_USER) {
			status = "BUSY";
			res = packet->FirstArgument;
			break;
		}
		conData->userName = packet->FirstArgument;

		tclData  = new ClientData;
		tclData->ioData = pIoData;
		tclData->cData = conData;

		UsersList[conData->userName] = tclData;
		JoinUserToChannel(conData->userName, "global", flag);
		status = "OK";
		res = conData->userName;
		break;
	case PacketTypeEnum::MSGT:
		type = PacketTypeEnum::MSGT;
		if (packet->FirstArgument.empty()) {
			status = "REJECT";
			res = "REJECT";
			info = "Reciever not specified";
			break;
		}
		if (packet->SecondArgument.empty()) {
			status = "REJECT";
			res = "REJECT";
			info = "Text not specified";
			break;
		}
		if (!SendChatMessage(conData->userName, packet->FirstArgument, packet->SecondArgument, info)) {
			status = "REJECT";
			res = "REJECT";
			break;
		}
		status = "OK";
		res = "OK";
		break;
	case PacketTypeEnum::USERS:
		type = PacketTypeEnum::USERS;
		if (packet->FirstArgument.empty()) {
			status = "OK";
			res = vector_to_string(GetUsersList());
			break;
		}

		v = GetUsersListFromChannel(packet->FirstArgument);
		if (!v.empty() && v[0] == "#-404") {
			status = "REJECT";
			break;
		}

		status = "OK";
		res = v.empty() ? "---" : vector_to_string(v);
		info = packet->FirstArgument;
		break;
	case PacketTypeEnum::CHANNELS:
		type = PacketTypeEnum::CHANNELS;
		status = "OK";
		res = vector_to_string(GetChannels());
		break;
	case PacketTypeEnum::JOIN:
		type = PacketTypeEnum::JOIN;
		res = packet->FirstArgument;
		if (res.empty()) {
			status = "REJECT";
			info = "Channel not specified";
			break;
		}
		if (!JoinUserToChannel(conData->userName, res, flag)) {
			status = "REJECT";
			info = "Already in channel";
			break;
		}
		status = "OK";
		info = flag ? "Create" : "Join";
		break;
	case PacketTypeEnum::LEAVE:
		type = PacketTypeEnum::LEAVE;
		res = packet->FirstArgument;
		if (res.empty()) {
			status = "REJECT";
			info = "Channel not specified";
			break;
		}
		if (!LeaveUserFromChannel(conData->userName, res, flag)) {
			status = "REJECT";
			info = "Not in channel or channel not exist";
			break;
		}
		status = "OK";
		info = flag ? "Delete" : "Left";
		break;
	default:
		pIoData->bytesRecv = 0;
		break;
	}

	newPacket = new Packet(type, status, res, info);
	encode = newPacket->Encode();
	strncpy_s(pIoData->buffer, encode.c_str(), 512);
	pIoData->bytesRecv = encode.length();
	printf_s("out(%s)> %s", conData->userName.c_str(), pIoData->buffer);
}