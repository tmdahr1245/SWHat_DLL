#include <stdio.h>
#include <wchar.h>
#include <winsock2.h>
#include <windows.h>
#include <winternl.h>

#define WINAPI_NUM 12 + 1

typedef struct _TRANSMIT_FILE_BUFFERS {
	LPVOID Head;
	DWORD  HeadLength;
	LPVOID Tail;
	DWORD  TailLength;
} TRANSMIT_FILE_BUFFERS, * PTRANSMIT_FILE_BUFFERS, * LPTRANSMIT_FILE_BUFFERS;

extern FARPROC OrgWinAPI[WINAPI_NUM];
extern LPVOID MyFunc[WINAPI_NUM];

//Socket
int WSAAPI Myconnect(SOCKET s, const sockaddr* name, int namelen);
int WSAAPI Mysend(SOCKET s, const char* buf, int len, int flags);
int WSAAPI Mysendto(SOCKET s, const char* buf, int len, DWORD flags, const struct sockaddr* to, int tolen);
int WSAAPI Myrecv(SOCKET s, char* buf, int len, int flags);
int WSAAPI Myrecvfrom(SOCKET s, char* buf, int len, int flags, struct sockaddr* from, int* fromlen);
SOCKET WSAAPI Myaccept(SOCKET s, struct sockaddr* addr, int* addrlen);
int PASCAL MyconnectEx(SOCKET s, const struct sockaddr* name, int namelen, PVOID lpSendBuffer, DWORD dwSendDataLength, LPDWORD lpdwBytesSent, LPOVERLAPPED lpOverlapped);
BOOL PASCAL MyTransmitFile(SOCKET hSocket, HANDLE hFile, DWORD nNumberOfBytesToWrite, DWORD nNumberOfBytesPerSend, LPOVERLAPPED lpOverlapped, LPTRANSMIT_FILE_BUFFERS lpTransmitBuffers, int dwFlags);
int WSAAPI MyWSARecv(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);
int WSAAPI MyWSARecvFrom(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags, struct sockaddr* lpFrom, LPINT lpFromlen, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);
int WSAAPI MyWSASend(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesSent, DWORD dwFlags, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);
int WSAAPI MyWSASendTo(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesSent, DWORD dwFlags, const struct sockaddr* lpTo, int iToLen, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);

//MISC
BOOL WINAPI MyCloseHandle(HANDLE hObject);
