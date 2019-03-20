#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>
#include <iostream>
#include <ctime>


#pragma comment (lib, "Ws2_32.lib")
//#pragma comment (lib, "Mswsock.lib")
//#pragma comment (lib, "AdvApi32.lib")
enum ClientState
{
	Login,
	Idle,
};

#define DEFAULT_BUFLEN 512
#define DEFAULT_PORT "27015"
#include "Packet.h"

struct IoOperationData {
	OVERLAPPED overlapped;
	WSABUF wsaBuf;
	CHAR buffer[DEFAULT_BUFLEN];
	DWORD bytesRecv;
};

struct ConnectionData {
	SOCKET socket;
	Packet *lastPacket;
};

int Quit(int result) {
	system("pause");
	return result;
}

DWORD WINAPI RecvWorkerThread(LPVOID pCompletionPort);
ClientState currentState = ClientState::Login;

void printWithTimestamp(string str) {
	time_t current_time;
	struct tm time_info;
	char timeString[9];

	time(&current_time);
	localtime_s(&time_info, &current_time);

	strftime(timeString, sizeof(timeString), "%H:%M:%S", &time_info);
	printf_s("[%s] %s\n$ ", timeString, str.c_str());
}

string helpString;
vector<string> helpTips = {
	"    ID#<username>\tsign in with specified <username>\n",
	"    MSG#<to>|<text>\tsend a message to user (or to a channelby starting\n    \t\t\tits name with '@')\n",
	"    USERS[#<channel>]\tprint users list, optionally print only users in\n    \t\t\ta <channel>\n",
	"    CHANNELS\t\tprint channels list\n",
	"    JOIN#<channel>\tjoin to the channel (or create a new one if it does\n    \t\t\tnot exist)\n",
	"    LEAVE#<channel>\tleave the channel (or delete the channel if you are\n    \t\t\tthe last user)\n",
	"    exit\t\tclose the application\n",
	"    help\t\tprint this help\n"
};

int __cdecl main(int argc, char *argv[])
{
	helpString = "";
	for (string& line : helpTips) {
		helpString += line + "\n";
	}
	helpString += " \n$ ";

	int error;

	// Запускаем Winsock
	WSADATA wsaData;
	error = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (error != 0) {
		printf("WSAStartup failed with error: %d\n$ ", error);
		return Quit(EXIT_FAILURE);
	}

	struct addrinfo hints;
	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	// Определяем адрес порт сервера
	struct addrinfo *serverAddr;
	error = -1;
	while (error != 0) {
		char server_address[200];
		printf_s("Enter server address:\n$ ");
		scanf_s(" %[^\n]s", server_address, (unsigned)_countof(server_address));

		if (server_address == "exit" or server_address == "^C") {
			WSACleanup();
			return Quit(EXIT_FAILURE);
		}

		error = getaddrinfo(server_address, DEFAULT_PORT, &hints, &serverAddr);
		if (error != 0) {
			printf("getaddrinfo failed with error: %d\n", error);
			if (GetLastError() == 11001)
			{
				printf_s("WSAHOST_NOT_FOUND 11001 (0x2AF9) No such host is known.\n\n$ ");
			}
			else
			{
				WSACleanup();
				return Quit(EXIT_FAILURE);
			}
			
		}
	}
	

	// Пытаемся подключиться к серверу по одному из опреденных адресов
	SOCKET clientSocket;
	for (struct addrinfo *ptr = serverAddr; ptr != NULL; ptr = ptr->ai_next) {

		// Пытаемся создать SOCKET для подключения
		clientSocket = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
		if (clientSocket == INVALID_SOCKET) {
			printf("socket failed with error: %ld\n$ ", WSAGetLastError());
			WSACleanup();
			return Quit(EXIT_FAILURE);
		}

		// Осуществлем подключение
		error = connect(clientSocket, ptr->ai_addr, (int)ptr->ai_addrlen);
		if (error == SOCKET_ERROR) {
			closesocket(clientSocket);
			clientSocket = INVALID_SOCKET;
			continue;
		}
		break;
	}

	freeaddrinfo(serverAddr);

	if (clientSocket == INVALID_SOCKET) {
		printf("Unable to connect to server!\n$ ");
		WSACleanup();
		return Quit(EXIT_FAILURE);
	}

	// Создаем порт завершения
	HANDLE hCompletionPort = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
	if (hCompletionPort == NULL) {
		printf("CreateIoCompletionPort failed with error %d\n$ ", GetLastError());
		WSACleanup();
		return Quit(EXIT_FAILURE);
	}

	// Создаем поток и передаем в него порт завершения
	DWORD threadId;
	HANDLE hThread = CreateThread(NULL, 0, RecvWorkerThread, hCompletionPort, 0, &threadId);
	if (hThread == NULL) {
		printf("CreateThread() failed with error %d\n$ ", GetLastError());
		WSACleanup();
		CloseHandle(hCompletionPort);
		return Quit(EXIT_FAILURE);
	}

	// Закрываем дескриптор потока, поток при этом не завершается
	CloseHandle(hThread);
	ConnectionData *pConnData = new ConnectionData;
	pConnData->socket = clientSocket;
	pConnData->lastPacket = NULL;
	// Связываем клиентский сокет с портом завершения
	if (CreateIoCompletionPort((HANDLE)clientSocket, hCompletionPort, (ULONG_PTR)pConnData, 0) == NULL) {
		printf("CreateIoCompletionPort failed with error %d\n$ ", GetLastError());
		return Quit(EXIT_FAILURE);
	}

	//  Создаем структуру для операций ввода-вывода и запускаем обработку
	IoOperationData *pIoData = new IoOperationData;
	ZeroMemory(&(pIoData->overlapped), sizeof(OVERLAPPED));
	pIoData->bytesRecv = 0;
	pIoData->wsaBuf.len = DEFAULT_BUFLEN;
	pIoData->wsaBuf.buf = pIoData->buffer;

	DWORD flags = 0;
	DWORD bytesRecv;
	if (WSARecv(clientSocket, &(pIoData->wsaBuf), 1, &bytesRecv, &flags, &(pIoData->overlapped), NULL) == SOCKET_ERROR) {
		if (WSAGetLastError() != ERROR_IO_PENDING) {
			printf("WSARecv failed with error %d\n$ ", WSAGetLastError());
			return Quit(EXIT_FAILURE);
		}
	}

	printf("Availible commands:\n    ID#<username>\tlog in\n    exit\t\tclose the app\n    help\t\tshow detailed help.\n$ ");
	char cmdline[400];
	string command;

	for (;;) {
		scanf_s(" %s", cmdline, (unsigned)_countof(cmdline));

		command = string(cmdline);
		if (command == "exit") {
			closesocket(clientSocket);
			WSACleanup();
			return Quit(EXIT_SUCCESS);
		}

		if (command == "help") {
			printf(helpString.c_str());
			continue;
		}

		// Convert to packet
		Packet *tp = new Packet(cmdline);
		if (tp->Command == PacketTypeEnum::INVALID) {
			printf("INVALID command\n$ ");
			continue;
		}

		string cstr = tp->Encode();
		const char * sendbuf = cstr.c_str();

		// Отправляем пакет
		int bytesSent = send(clientSocket, sendbuf, (int)strlen(sendbuf), 0);
		if (bytesSent == SOCKET_ERROR) {
			printf("send failed with error: %d\n$ ", WSAGetLastError());
			closesocket(clientSocket);
			WSACleanup();
			return Quit(EXIT_FAILURE);
		}
	}
}

DWORD WINAPI RecvWorkerThread(LPVOID pCompletionPort) {
	HANDLE hCompletionPort = (HANDLE)pCompletionPort;

	for (; ; ) {
		DWORD bytesTransferred;
		ConnectionData *pConnectionData;
		IoOperationData *pIoData;
		if (GetQueuedCompletionStatus(hCompletionPort, &bytesTransferred,
			(PULONG_PTR)&pConnectionData, (LPOVERLAPPED *)&pIoData, INFINITE) == 0) {
			printf_s("GetQueuedCompletionStatus() failed with error %d\n$ ", GetLastError());
			return 0;
		}

		// Проверим, не было ли проблем с сокетом и не было ли закрыто соединение
		if (bytesTransferred == 0) {
			closesocket(pConnectionData->socket);
			delete pConnectionData;
			delete pIoData;
			continue;
		}

		pIoData->bytesRecv = bytesTransferred;

		string rawPacket = string(pIoData->wsaBuf.buf, (size_t)pIoData->bytesRecv);
		//printf("[DEBUG] <in %s\n", rawPacket.c_str());
		Packet * recvPacket = new Packet(pIoData->wsaBuf.buf);

		if (recvPacket->Command == PacketTypeEnum::INVALID) {
			printf_s("500 Internal Server Error\n$ ");
		}

		pConnectionData->lastPacket = recvPacket;

		switch (currentState)
		{
		case Login:
			if (recvPacket->Command == PacketTypeEnum::ID) {
				if (recvPacket->FirstArgument == "REJECT") {
					printf_s("Username %s busy, please try another name\n$ ", recvPacket->SecondArgument.c_str());
					break;
				}
				if (recvPacket->FirstArgument == "EMPTY") {
					printf_s("%s \n$ ", recvPacket->ThirdArgument.c_str());
					break;
				}
				currentState = ClientState::Idle;
				printf_s("Hello %s!\nUse <MSG#'To'|'Message'> command for send message, <help> for print help.\n$ ", recvPacket->SecondArgument.c_str());
			}
			break;
		case Idle:
			if (recvPacket->Command == PacketTypeEnum::ID) {
				if (recvPacket->FirstArgument != "OK") {
					printf_s("%s \n$ ", recvPacket->ThirdArgument.c_str());
					break;
				}
			}
			if (recvPacket->Command == PacketTypeEnum::USERS) {
				if (recvPacket->FirstArgument != "OK") {
					printf_s("Specified channel not found\n$ ");
					break;
				}

				if (recvPacket->ThirdArgument.empty()) {
					printf_s("Online users:\n%s\n$ ", recvPacket->SecondArgument.c_str());
				} else {
					printf_s("Online users[%s]:\n%s\n$ ", recvPacket->ThirdArgument.c_str(), recvPacket->SecondArgument.c_str());
				}
				break;
			}
			if (recvPacket->Command == PacketTypeEnum::CHANNELS) {
				if (recvPacket->FirstArgument != "OK") {
					printf_s("%s\n$ ", recvPacket->ThirdArgument.empty() ?  "Something went wrong" : recvPacket->ThirdArgument.c_str());
					break;
				}
				printf_s("Online channels:\n%s\n$ ", recvPacket->SecondArgument.c_str());
				break;
			}
			if (recvPacket->Command == PacketTypeEnum::JOIN) {
				if (recvPacket->FirstArgument != "OK") {
					printf_s("%s\n$ ", recvPacket->ThirdArgument.empty() ? "Something went wrong" : recvPacket->ThirdArgument.c_str());
					break;
				}
				if (recvPacket->ThirdArgument == "Create") {
					printf_s("You create @%s\n$ ", recvPacket->SecondArgument.c_str());
				} else {
					printf_s("You join to @%s\n$ ", recvPacket->SecondArgument.c_str());
				}
				break;
			}
			if (recvPacket->Command == PacketTypeEnum::LEAVE) {
				if (recvPacket->FirstArgument != "OK") {
					printf_s("%s\n$ ", recvPacket->ThirdArgument.empty() ? "Something went wrong" : recvPacket->ThirdArgument.c_str());
					break;
				}
				if (recvPacket->ThirdArgument == "Delete") {
					printf_s("You delete @%s cause no more users in it\n$ ", recvPacket->SecondArgument.c_str());
				}
				else {
					printf_s("You left @%s\n$ ", recvPacket->SecondArgument.c_str());
				}
				break;
			}
			if (recvPacket->Command == PacketTypeEnum::MSGT) {
				if (recvPacket->FirstArgument != "OK") {
					printf_s("%s\n$ ", recvPacket->ThirdArgument.empty() ? "Something went wrong" : recvPacket->ThirdArgument.c_str());
					break;
				}
				printf_s("  ");
				break;
			}
			if (recvPacket->Command == PacketTypeEnum::MSGIN) {

				if (recvPacket->ThirdArgument.empty()) {
					printWithTimestamp(recvPacket->FirstArgument + ": " + recvPacket->SecondArgument);
					break;
				}
				printWithTimestamp(recvPacket->FirstArgument + " (@" + recvPacket->ThirdArgument + "): " + recvPacket->SecondArgument);
				break;
			}
			break;
		default:
			break;
		}

		DWORD bytesRecv;
		pIoData->bytesRecv = 0;
		DWORD flags = 0;
		ZeroMemory(&(pIoData->overlapped), sizeof(OVERLAPPED));
		pIoData->wsaBuf.len = DEFAULT_BUFLEN;
		pIoData->wsaBuf.buf = pIoData->buffer;
		if (WSARecv(pConnectionData->socket, &(pIoData->wsaBuf), 1, &bytesRecv, &flags, &(pIoData->overlapped), NULL) == SOCKET_ERROR) {
			if (WSAGetLastError() != ERROR_IO_PENDING) {
				printf_s("WSARecv failed with error %d\n$ ", WSAGetLastError());
				return 0;
			}
		}
	}
}
