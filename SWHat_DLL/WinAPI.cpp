#include "WinAPI.hpp"
#include "Log.hpp"
#include "Util.hpp"
#include <stdio.h>
#include <tchar.h>
#pragma warning(disable: 4996)
#pragma comment(lib, "ws2_32.lib")

FARPROC OrgWinAPI[WINAPI_NUM]= { NULL, };

//Function Pointer Definition
typedef int (WSAAPI* PFMyconnect)(SOCKET s, const sockaddr* name, int namelen);
typedef int (WSAAPI* PFMysend)(SOCKET s, const char* buf, int len, int flags);
typedef int (WSAAPI* PFMysendto)(SOCKET s, const char* buf, int len, DWORD flags, const struct sockaddr* to, int tolen);
typedef int (WSAAPI* PFMyrecv)(SOCKET s, char* buf, int len, int flags);
typedef int (WSAAPI* PFMyrecvfrom)(SOCKET s, char* buf, int len, int flags, struct sockaddr* from, int* fromlen);
typedef SOCKET(WSAAPI* PFMyaccept)(SOCKET s, struct sockaddr* addr, int* addrlen);
typedef int (PASCAL* PFMyconnectEx)(SOCKET s, const struct sockaddr* name, int namelen, PVOID lpSendBuffer, DWORD dwSendDataLength, LPDWORD lpdwBytesSent, LPOVERLAPPED lpOverlapped);
typedef BOOL(PASCAL* PFMyTransmitFile)(SOCKET hSocket, HANDLE hFile, DWORD nNumberOfBytesToWrite, DWORD nNumberOfBytesPerSend, LPOVERLAPPED lpOverlapped, LPTRANSMIT_FILE_BUFFERS lpTransmitBuffers, int dwFlags);
typedef int (WSAAPI* PFMyWSARecv)(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);
typedef int (WSAAPI* PFMyWSARecvFrom)(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags, struct sockaddr* lpFrom, LPINT lpFromlen, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);
typedef int (WSAAPI* PFMyWSASend)(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesSent, DWORD dwFlags, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);
typedef int (WSAAPI* PFMyWSASendTo)(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesSent, DWORD dwFlags, const struct sockaddr* lpTo, int iToLen, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);
typedef BOOL(WINAPI* PFMyCloseHandle)(HANDLE hObject);

int WSAAPI Myconnect(
	SOCKET s, 
	const sockaddr* name,//SOCKADDR_IN
	int namelen
) {
	int ret;
	//OutputDebugString(TEXT("connect"));
	//SOCKET_ERROR가 리턴값으로 나오면 '연결 시도했지만 실패라는것' 까지 로깅 해줘도 좋을듯
	ret = ((PFMyconnect)OrgWinAPI[0])(s, name, namelen);
	wchar_t buf[100];
	SOCKADDR_IN* sock = (SOCKADDR_IN*)name;

	_stprintf(buf, L"connect, socket : %x, port : %d, ip : %s", s, ntohs(sock->sin_port), ConvertMultibyteToUnicode(inet_ntoa(sock->sin_addr)));
	if (ret == SOCKET_ERROR)
		lstrcat(buf, L" try to connect but failed");
	else
		lstrcat(buf, L" connect success");
	OutputDebugStringW(buf);

	vector<pair<string, pair<string, string>>> v;
	v.emplace_back(make_pair("string", make_pair("api", "connect")));
	char tt[100];
	sprintf(tt, "0x%x", s);
	v.emplace_back(make_pair("int", make_pair("socket", tt)));
	sprintf(tt, "%d", ntohs(sock->sin_port));
	v.emplace_back(make_pair("int", make_pair("port", tt)));
	v.emplace_back(make_pair("int", make_pair("ip", inet_ntoa(sock->sin_addr))));
	if (ret == SOCKET_ERROR)
		v.emplace_back(make_pair("string", make_pair("Status", "fail")));
	else
		v.emplace_back(make_pair("string", make_pair("Status", "success")));
	Log(v);
	//Log2(buf);
	return ret;
}
int WSAAPI Mysend(
	SOCKET s, 
	const char* buf, 
	int len,
	int flags
) {
	int ret;
	wchar_t b[1000];
	_stprintf(b, L"send, socket : %x", s);
	//Log2(b);
	OutputDebugString(TEXT("send"));
	ret = ((PFMysend)OrgWinAPI[1])(s, buf, len, flags);
	vector<pair<string, pair<string, string>>> v;
	v.emplace_back(make_pair("string", make_pair("api", "send")));
	char tt[100];
	sprintf(tt, "0x%x", s);
	v.emplace_back(make_pair("int", make_pair("socket", tt)));
	sprintf(tt, "0x%x", ret);
	v.emplace_back(make_pair("int", make_pair("ret", tt)));
	LogWithBuffer(v, (wchar_t*)buf, len, "buf");
	return ret;
}
int WSAAPI Mysendto(
	SOCKET s,
	const char* buf,
	int len,
	DWORD flags, 
	const struct sockaddr* to,
	int tolen
) {
	int ret;
	OutputDebugString(TEXT("sendto"));
	ret = ((PFMysendto)OrgWinAPI[2])(s, buf, len, flags, to, tolen);
	return ret;
}
int WSAAPI Myrecv(
	SOCKET s, 
	char* buf, 
	int len, 
	int flags
) {
	int ret;
	OutputDebugString(TEXT("recv"));
	ret = ((PFMyrecv)OrgWinAPI[3])(s, buf, len, flags);
	return ret;
}
int WSAAPI Myrecvfrom(
	SOCKET s,
	char* buf,
	int len, 
	int flags,
	struct sockaddr* from, 
	int* fromlen
) {
	int ret;
	OutputDebugString(TEXT("recvfrom"));
	ret = ((PFMyrecvfrom)OrgWinAPI[4])(s, buf, len, flags, from, fromlen);
	return ret;
}
SOCKET WSAAPI Myaccept(
	SOCKET s,
	struct sockaddr* addr, 
	int* addrlen
) {
	SOCKET ret;
	OutputDebugString(TEXT("accept"));
	ret = ((PFMyaccept)OrgWinAPI[5])(s, addr, addrlen);
	return ret;
}
int PASCAL MyconnectEx(
	SOCKET s, 
	const struct sockaddr* name,
	int namelen, 
	PVOID lpSendBuffer, 
	DWORD dwSendDataLength,
	LPDWORD lpdwBytesSent, 
	LPOVERLAPPED lpOverlapped
) {
	int ret;
	OutputDebugString(TEXT("connectEx"));
	ret = ((PFMyconnectEx)OrgWinAPI[6])(s, name, namelen, lpSendBuffer, dwSendDataLength, lpdwBytesSent, lpOverlapped);
	return ret;
}
BOOL PASCAL MyTransmitFile(
	SOCKET hSocket, 
	HANDLE hFile,
	DWORD nNumberOfBytesToWrite, 
	DWORD nNumberOfBytesPerSend,
	LPOVERLAPPED lpOverlapped, 
	LPTRANSMIT_FILE_BUFFERS lpTransmitBuffers,
	int dwFlags
) {
	int ret;
	OutputDebugString(TEXT("TransmitFile"));
	ret = ((PFMyTransmitFile)OrgWinAPI[7])(hSocket, hFile, nNumberOfBytesToWrite, nNumberOfBytesPerSend, lpOverlapped, lpTransmitBuffers, dwFlags);
	return ret;
}
int WSAAPI MyWSARecv(
	SOCKET s,
	LPWSABUF lpBuffers, 
	DWORD dwBufferCount, 
	LPDWORD lpNumberOfBytesRecvd,
	LPDWORD lpFlags, 
	LPWSAOVERLAPPED lpOverlapped,
	LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
) {
	int ret;
	OutputDebugString(TEXT("WSARecv"));
	ret = ((PFMyWSARecv)OrgWinAPI[8])(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, lpOverlapped, lpCompletionRoutine);
	return ret;
}
int WSAAPI MyWSARecvFrom(
	SOCKET s,
	LPWSABUF lpBuffers,
	DWORD dwBufferCount, 
	LPDWORD lpNumberOfBytesRecvd, 
	LPDWORD lpFlags, 
	struct sockaddr* lpFrom,
	LPINT lpFromlen, 
	LPWSAOVERLAPPED lpOverlapped, 
	LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
) {
	int ret;
	OutputDebugString(TEXT("WSARecvFrom"));
	ret = ((PFMyWSARecvFrom)OrgWinAPI[9])(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, lpFrom, lpFromlen, lpOverlapped, lpCompletionRoutine);
	return ret;
}
int WSAAPI MyWSASend(
	SOCKET s, 
	LPWSABUF lpBuffers, 
	DWORD dwBufferCount, 
	LPDWORD lpNumberOfBytesSent,
	DWORD dwFlags, 
	LPWSAOVERLAPPED lpOverlapped,
	LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
) {
	int ret;
	OutputDebugString(TEXT("WSASend"));
	ret = ((PFMyWSASend)OrgWinAPI[10])(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpOverlapped, lpCompletionRoutine);
	return ret;
}
int WSAAPI MyWSASendTo(
	SOCKET s,
	LPWSABUF lpBuffers,
	DWORD dwBufferCount,
	LPDWORD lpNumberOfBytesSent,
	DWORD dwFlags, 
	const struct sockaddr* lpTo,
	int iToLen, 
	LPWSAOVERLAPPED lpOverlapped,
	LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
) {
	int ret;
	OutputDebugString(TEXT("WSASendTo"));
	ret = ((PFMyWSASendTo)OrgWinAPI[11])(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpTo, iToLen, lpOverlapped, lpCompletionRoutine);
	return ret;
}
BOOL WINAPI MyCloseHandle(HANDLE hObject) {
	int ret;
	wchar_t buf[100];
	_stprintf(buf, L"MyCloseHandle, handle : %x, ", hObject);
	OutputDebugString(buf);
	//Log2(buf);
	ret = ((PFMyCloseHandle)OrgWinAPI[12])(hObject);
	vector<pair<string, pair<string, string>>> v;
	v.emplace_back(make_pair("string", make_pair("api", "CloseHandle")));
	char tt[100];
	sprintf(tt, "0x%x", hObject);
	v.emplace_back(make_pair("int", make_pair("HANDLE", tt)));
	sprintf(tt, "0x%x", ret);
	v.emplace_back(make_pair("int", make_pair("ret", tt)));
	Log(v);
	return ret;
}
LPVOID MyFunc[WINAPI_NUM] = {
	Myconnect, 
	Mysend,
	Mysendto,
	Myrecv, 
	Myrecvfrom,
	Myaccept,
	MyconnectEx, 
	MyTransmitFile,
	MyWSARecv,
	MyWSARecvFrom,
	MyWSASend, 
	MyWSASendTo,
	MyCloseHandle
};