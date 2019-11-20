#include "WinAPI.hpp"
#include "Log.hpp"
#include "Util.hpp"
#include <stdio.h>
#include <tchar.h>
#include <MSWSock.h>
#pragma warning(disable: 4996)
#pragma comment(lib, "ws2_32.lib")

LPVOID OrgWinAPI[WINAPI_NUM]= { NULL, };

//Function Pointer Definition
typedef int (WSAAPI* PFMyconnect)(SOCKET s, const sockaddr* name, int namelen);
typedef int (WSAAPI* PFMysend)(SOCKET s, const char* buf, int len, int flags);
typedef int (WSAAPI* PFMysendto)(SOCKET s, const char* buf, int len, DWORD flags, const struct sockaddr* to, int tolen);
typedef int (WSAAPI* PFMyrecv)(SOCKET s, char* buf, int len, int flags);
typedef int (WSAAPI* PFMyrecvfrom)(SOCKET s, char* buf, int len, int flags, struct sockaddr* from, int* fromlen);
typedef SOCKET(WSAAPI* PFMyaccept)(SOCKET s, struct sockaddr* addr, int* addrlen);
//typedef int (PASCAL* PFMyconnectEx)(SOCKET s, const struct sockaddr* name, int namelen, PVOID lpSendBuffer, DWORD dwSendDataLength, LPDWORD lpdwBytesSent, LPOVERLAPPED lpOverlapped);
//typedef BOOL(PASCAL* PFMyTransmitFile)(SOCKET hSocket, HANDLE hFile, DWORD nNumberOfBytesToWrite, DWORD nNumberOfBytesPerSend, LPOVERLAPPED lpOverlapped, LPTRANSMIT_FILE_BUFFERS lpTransmitBuffers, int dwFlags);
typedef int (WSAAPI* PFMyWSARecv)(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);
typedef int (WSAAPI* PFMyWSARecvFrom)(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags, struct sockaddr* lpFrom, LPINT lpFromlen, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);
typedef int (WSAAPI* PFMyWSASend)(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesSent, DWORD dwFlags, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);
typedef int (WSAAPI* PFMyWSASendTo)(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesSent, DWORD dwFlags, const struct sockaddr* lpTo, int iToLen, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);
typedef int (WSAAPI* PFMyclosesocket)(SOCKET s);
typedef int (WSAAPI* PFMyWSAConnect)(SOCKET s, const sockaddr* name, int namelen, LPWSABUF lpCallerData, LPWSABUF lpCalleeData, LPQOS lpSQOS, LPQOS lpGQOS);
//typedef BOOL(WINAPI* PFMyCloseHandle)(HANDLE hObject);
typedef SC_HANDLE (WINAPI* PFMyOpenServiceA)(SC_HANDLE hSCManager, LPCTSTR lpServiceName, DWORD dwDesiredAccess);
typedef SC_HANDLE (WINAPI* PFMyOpenServiceW)(SC_HANDLE hSCManager, LPWSTR lpServiceName, DWORD dwDesiredAccess);
typedef SC_HANDLE (WINAPI* PFMyCreateServiceA)(SC_HANDLE hSCManager, LPCSTR lpServiceName, LPCSTR lpDisplayName, DWORD dwDesiredAccess, DWORD dwServiceType, DWORD dwStartType, DWORD dwErrorControl, LPCSTR lpBinaryPathName, LPCSTR lpLoadOrderGroup, LPDWORD lpdwTagId, LPCSTR lpDependencies, LPCSTR lpServiceStartName, LPCSTR lpPassword);
typedef SC_HANDLE (WINAPI* PFMyCreateServiceW)(SC_HANDLE hSCManager, LPCWSTR lpServiceName, LPCWSTR lpDisplayName, DWORD dwDesiredAccess, DWORD dwServiceType, DWORD dwStartType, DWORD dwErrorControl, LPCWSTR lpBinaryPathName, LPCWSTR lpLoadOrderGroup, LPDWORD lpdwTagId, LPCWSTR lpDependencies, LPCWSTR lpServiceStartName, LPCWSTR lpPassword);
typedef BOOL (WINAPI* PFMyStartServiceA)(SC_HANDLE hService, DWORD dwNumServiceArgs, LPCTSTR* lpServiceArgVectors);
typedef BOOL (WINAPI* PFMyStartServiceW)(SC_HANDLE hService, DWORD dwNumServiceArgs, LPCWSTR* lpServiceArgVectors);
typedef BOOL (WINAPI* PFMyControlService)(SC_HANDLE hService, DWORD dwControl, LPSERVICE_STATUS lpServiceStatus);
typedef BOOL (WINAPI* PFMyDeleteService)(SC_HANDLE hService);
typedef BOOL (WINAPI* PFMyCloseServiceHandle)(SC_HANDLE hSCObject);
typedef HRESULT(WINAPI* PFMyURLDownloadToFileA)(LPUNKNOWN pCaller, LPCSTR szURL, LPCSTR szFileName, DWORD dwReserved, LPBINDSTATUSCALLBACK lpfnCB);
typedef HRESULT(WINAPI* PFMyURLDownloadToFileW)(LPUNKNOWN pCaller, LPCWSTR szURL, LPCWSTR szFileName, DWORD dwReserved, LPBINDSTATUSCALLBACK lpfnCB);
typedef BOOL (WINAPI* PFMyInternetReadFile)(HINTERNET hFile, LPVOID lpBuffer, DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead);
typedef BOOL (WINAPI* PFMyInternetWriteFile)(HINTERNET hFile, LPCVOID lpBuffer, DWORD dwNumberOfBytesToWrite, LPDWORD lpdwNumberOfBytesWritten);
typedef HINTERNET(WINAPI* PFMyInternetOpenA)(LPCSTR lpszAgent, DWORD dwAccessType, LPCSTR lpszProxy, LPCSTR lpszProxyBypass, DWORD dwFlags);
typedef HINTERNET(WINAPI* PFMyInternetOpenW)(LPCWSTR lpszAgent, DWORD dwAccessType, LPCWSTR lpszProxy, LPCWSTR lpszProxyBypass, DWORD dwFlags);
typedef HINTERNET(WINAPI* PFMyInternetConnectA)(HINTERNET hInternet, LPCSTR lpszServerName, INTERNET_PORT nServerPort, LPCSTR lpszUserName, LPCSTR lpszPassword, DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext);
typedef HINTERNET(WINAPI* PFMyInternetConnectW)(HINTERNET hInternet, LPCWSTR lpszServerName, INTERNET_PORT nServerPort, LPCWSTR lpszUserName, LPCWSTR lpszPassword, DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext);
typedef HINTERNET(WINAPI* PFMyInternetOpenUrlA)(HINTERNET hInternet, LPCSTR lpszUrl, LPCSTR lpszHeaders, DWORD dwHeadersLength, DWORD dwFlags, DWORD_PTR dwContext);
typedef HINTERNET(WINAPI* PFMyInternetOpenUrlW)(HINTERNET hInternet, LPCWSTR lpszUrl, LPCWSTR lpszHeaders, DWORD dwHeadersLength, DWORD dwFlags, DWORD_PTR dwContext);
typedef HINTERNET(WINAPI* PFMyHttpOpenRequestA)(HINTERNET hConnect, LPCSTR lpszVerb, LPCSTR lpszObjectName, LPCSTR lpszVersion, LPCSTR lpszReferrer, LPCSTR* lplpszAcceptTypes, DWORD dwFlags, DWORD_PTR dwContext);
typedef HINTERNET(WINAPI* PFMyHttpOpenRequestW)(HINTERNET hConnect, LPCWSTR lpszVerb, LPCWSTR lpszObjectName, LPCWSTR lpszVersion, LPCWSTR lpszReferrer, LPCWSTR* lplpszAcceptTypes, DWORD dwFlags, DWORD_PTR dwContext);
typedef BOOL (WINAPI* PFMyHttpSendRequestA)(HINTERNET hRequest, LPCSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength);
typedef BOOL (WINAPI* PFMyHttpSendRequestW)(HINTERNET hRequest, LPCWSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength);
typedef int (WSAAPI* PFMyWSAIoctl)(SOCKET s, DWORD dwIoControlCode, LPVOID lpvInBuffer, DWORD cbInBuffer, LPVOID lpvOutBuffer, DWORD cbOutBuffer, LPDWORD lpcbBytesReturned, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);
typedef BOOL (WSAAPI* PFMyConnectex)(SOCKET s, const sockaddr* name, int namelen, PVOID lpSendBuffer, DWORD dwSendDataLength, LPDWORD lpdwBytesSent, LPOVERLAPPED lpOverlapped);
typedef LSTATUS (WINAPI* PFMyRegCreateKeyA)(HKEY hKey, LPCSTR lpSubKey, PHKEY phkResult);
typedef LSTATUS (WINAPI* PFMyRegCreateKeyW)(HKEY hKey, LPCWSTR lpSubKey, PHKEY phkResult);
typedef LSTATUS (WINAPI* PFMyRegCreateKeyExA)(HKEY hKey, LPCSTR lpSubKey, DWORD Reserved, LPSTR lpClass, DWORD dwOptions, REGSAM samDesired, const LPSECURITY_ATTRIBUTES lpSecurityAttributes, PHKEY phkResult, LPDWORD lpdwDisposition);
typedef LSTATUS (WINAPI* PFMyRegCreateKeyExW)(HKEY hKey, LPCWSTR lpSubKey, DWORD Reserved, LPWSTR lpClass, DWORD dwOptions, REGSAM samDesired, const LPSECURITY_ATTRIBUTES lpSecurityAttributes, PHKEY phkResult, LPDWORD lpdwDisposition);
typedef LSTATUS (WINAPI* PFMyRegOpenKeyA)(HKEY hKey, LPCSTR lpSubKey, PHKEY phkResult);
typedef LSTATUS (WINAPI* PFMyRegOpenKeyW)(HKEY hKey, LPCWSTR lpSubKey, PHKEY phkResult);
typedef LSTATUS (WINAPI* PFMyRegOpenKeyExA)(HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult);
typedef LSTATUS (WINAPI* PFMyRegOpenKeyExW)(HKEY hKey, LPCWSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult);
typedef LSTATUS (WINAPI* PFMyRegSetValueA)(HKEY hKey, LPCSTR lpSubKey, DWORD dwType, LPCSTR lpData, DWORD cbData);
typedef LSTATUS (WINAPI* PFMyRegSetValueW)(HKEY hKey, LPCWSTR lpSubKey, DWORD dwType, LPCWSTR lpData, DWORD cbData);
typedef LSTATUS (WINAPI* PFMyRegSetValueExA)(HKEY hKey, LPCSTR lpValueName, DWORD Reserved, DWORD dwType, const BYTE* lpData, DWORD cbData);
typedef LSTATUS (WINAPI* PFMyRegSetValueExW)(HKEY hKey, LPCWSTR lpValueName, DWORD Reserved, DWORD dwType, const BYTE* lpData, DWORD cbData);
typedef LSTATUS (WINAPI* PFMyRegSetKeyValueA)(HKEY hKey, LPCSTR lpSubKey, LPCSTR lpValueName, DWORD dwType, LPCVOID lpData, DWORD cbData);
typedef LSTATUS (WINAPI* PFMyRegSetKeyValueW)(HKEY hKey, LPCWSTR lpSubKey, LPCWSTR lpValueName, DWORD dwType, LPCVOID lpData, DWORD cbData);
typedef LSTATUS (WINAPI* PFMyRegDeleteKeyA)(HKEY hKey, LPCSTR lpSubKey);
typedef LSTATUS (WINAPI* PFMyRegDeleteKeyW)(HKEY hKey, LPCWSTR lpSubKey);
typedef LSTATUS (WINAPI* PFMyRegDeleteKeyExA)(HKEY hKey, LPCSTR lpSubKey, REGSAM samDesired, DWORD Reserved);
typedef LSTATUS (WINAPI* PFMyRegDeleteKeyExW)(HKEY hKey, LPCWSTR lpSubKey, REGSAM samDesired, DWORD Reserved);
typedef LSTATUS (WINAPI* PFMyRegDeleteValueA)(HKEY hKey, LPCSTR lpValueName);
typedef LSTATUS (WINAPI* PFMyRegDeleteValueW)(HKEY hKey, LPCWSTR lpValueName);
typedef LSTATUS (WINAPI* PFMyRegDeleteKeyValueA)(HKEY hKey, LPCSTR lpSubKey, LPCSTR lpValueName);
typedef LSTATUS (WINAPI* PFMyRegDeleteKeyValueW)(HKEY hKey, LPCWSTR lpSubKey, LPCWSTR lpValueName);
typedef LSTATUS (WINAPI* PFMyRegCloseKey)(HKEY hKey);
int WSAAPI Myconnect(
	SOCKET s, 
	const sockaddr* name,
	int namelen
) {
	int ret;

	ret = ((PFMyconnect)OrgWinAPI[0])(s, name, namelen);
	SOCKADDR_IN* sock = (SOCKADDR_IN*)name;
	///////////////////////////////////////////////
	wchar_t buf[100];
	_stprintf(buf, L"connect, socket : %x, port : %d, ip : %s", s, ntohs(sock->sin_port), ConvertMultibyteToUnicode(inet_ntoa(sock->sin_addr)));
	if (ret == SOCKET_ERROR)
		lstrcat(buf, L" try to connect but failed");
	else
		lstrcat(buf, L" connect success");
	OutputDebugStringW(buf);
	///////////////////////////////////////////////

	vector<pair<string, string>> v;
	v.push_back({ "api", "connect" });
	push_back_format(v, "0x%x", s, "socket");
	push_back_format(v, "%d", ntohs(sock->sin_port), "port");
	v.push_back({ "ip", inet_ntoa(sock->sin_addr) });
	if (ret == SOCKET_ERROR)
		v.push_back({ "Status", "Fail" });
	else
		v.push_back({ "Status", "Success" });

	InsertHandle((HANDLE)s);
	Log(v);

	return ret;
}
int WSAAPI Mysend(
	SOCKET s, 
	const char* buf, 
	int len,
	int flags
) {
	int ret;
	///////////////////////////////////////////////
	OutputDebugString(TEXT("send"));
	///////////////////////////////////////////////

	ret = ((PFMysend)OrgWinAPI[1])(s, buf, len, flags);

	vector<pair<string, string>> v;
	v.push_back({ "api", "send" });
	push_back_format(v, "0x%x", s, "socket");
	push_back_format(v, "0x%x", ret, "ret");
	push_back_format(v, "0x%x", len, "len");

	Log(v, (wchar_t*)buf, len, "buf");

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
	///////////////////////////////////////////////
	OutputDebugString(TEXT("sendto"));
	///////////////////////////////////////////////

	ret = ((PFMysendto)OrgWinAPI[2])(s, buf, len, flags, to, tolen);
	SOCKADDR_IN* sock = (SOCKADDR_IN*)to;
	vector<pair<string, string>> v;
	v.push_back({ "api", "sendto" });
	push_back_format(v, "0x%x", s, "socket");
	push_back_format(v, "%d", ntohs(sock->sin_port), "port");
	v.push_back({ "ip", inet_ntoa(sock->sin_addr) });
	push_back_format(v, "0x%x", ret, "ret");
	push_back_format(v, "0x%x", len, "len");

	Log(v, (wchar_t*)buf, len, "buf");

	return ret;
}
int WSAAPI Myrecv(
	SOCKET s, 
	char* buf, 
	int len, 
	int flags
) {
	int ret;
	///////////////////////////////////////////////
	OutputDebugString(TEXT("recv"));
	///////////////////////////////////////////////
	ret = ((PFMyrecv)OrgWinAPI[3])(s, buf, len, flags);

	vector<pair<string, string>> v;
	v.push_back({ "api", "recv" });
	push_back_format(v, "0x%x", s, "socket");
	push_back_format(v, "0x%x", ret, "ret");
	push_back_format(v, "0x%x", len, "len");

	Log(v, (wchar_t*)buf, len, "buf");

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
	///////////////////////////////////////////////
	OutputDebugString(TEXT("recvfrom"));
	///////////////////////////////////////////////
	ret = ((PFMyrecvfrom)OrgWinAPI[4])(s, buf, len, flags, from, fromlen);

	SOCKADDR_IN* sock = (SOCKADDR_IN*)from;
	vector<pair<string, string>> v;
	v.push_back({ "api", "recvfrom" });
	push_back_format(v, "0x%x", s, "socket");
	push_back_format(v, "%d", ntohs(sock->sin_port), "port");
	v.push_back({ "ip", inet_ntoa(sock->sin_addr) });
	push_back_format(v, "0x%x", ret, "ret");
	push_back_format(v, "0x%x", len, "len");

	Log(v, (wchar_t*)buf, len, "buf");
	return ret;
}
SOCKET WSAAPI Myaccept(
	SOCKET s,
	struct sockaddr* addr, 
	int* addrlen
) {
	SOCKET ret;
	///////////////////////////////////////////////
	OutputDebugString(TEXT("accept"));
	///////////////////////////////////////////////
	ret = ((PFMyaccept)OrgWinAPI[5])(s, addr, addrlen);

	SOCKADDR_IN* sock = (SOCKADDR_IN*)addr;
	vector<pair<string, string>> v;
	v.push_back({ "api", "accept" });
	push_back_format(v, "0x%x", s, "socket");
	push_back_format(v, "%d", ntohs(sock->sin_port), "port");
	v.push_back({ "ip", inet_ntoa(sock->sin_addr) });
	push_back_format(v, "0x%x", ret, "ret");

	InsertHandle((HANDLE)s);
	Log(v);
	return ret;
}/*
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
	///////////////////////////////////////////////
	OutputDebugString(TEXT("connectEx"));
	///////////////////////////////////////////////
	ret = ((PFMyconnectEx)OrgWinAPI[6])(s, name, namelen, lpSendBuffer, dwSendDataLength, lpdwBytesSent, lpOverlapped);

	InsertHandle((HANDLE)s);

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
	///////////////////////////////////////////////
	OutputDebugString(TEXT("TransmitFile"));
	///////////////////////////////////////////////
	ret = ((PFMyTransmitFile)OrgWinAPI[7])(hSocket, hFile, nNumberOfBytesToWrite, nNumberOfBytesPerSend, lpOverlapped, lpTransmitBuffers, dwFlags);
	return ret;
}*/
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
	///////////////////////////////////////////////
	OutputDebugString(TEXT("WSARecv"));
	///////////////////////////////////////////////
	ret = ((PFMyWSARecv)OrgWinAPI[6])(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, lpOverlapped, lpCompletionRoutine);

	vector<pair<string, string>> v;
	v.push_back({ "api", "WSARecv" });
	push_back_format(v, "0x%x", s, "socket");
	push_back_format(v, "0x%x", ret, "ret");
	push_back_format(v, "0x%x", lpBuffers->len, "len");

	Log(v, (wchar_t*)lpBuffers->buf, lpBuffers->len, "buf");
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
	///////////////////////////////////////////////
	OutputDebugString(TEXT("WSARecvFrom"));
	///////////////////////////////////////////////
	ret = ((PFMyWSARecvFrom)OrgWinAPI[7])(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, lpFrom, lpFromlen, lpOverlapped, lpCompletionRoutine);

	SOCKADDR_IN* sock = (SOCKADDR_IN*)lpFrom;
	vector<pair<string, string>> v;
	v.push_back({ "api", "WSARecvFrom" });
	push_back_format(v, "0x%x", s, "socket");
	push_back_format(v, "%d", ntohs(sock->sin_port), "port");
	v.push_back({ "ip", inet_ntoa(sock->sin_addr) });
	push_back_format(v, "0x%x", ret, "ret");
	push_back_format(v, "0x%x", lpBuffers->len, "len");

	Log(v, (wchar_t*)lpBuffers->buf, lpBuffers->len, "buf"); 
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
	///////////////////////////////////////////////
	OutputDebugString(TEXT("WSASend"));
	///////////////////////////////////////////////
	ret = ((PFMyWSASend)OrgWinAPI[8])(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpOverlapped, lpCompletionRoutine);
	
	vector<pair<string, string>> v;
	v.push_back({ "api", "WSASend" });
	push_back_format(v, "0x%x", s, "socket");
	push_back_format(v, "0x%x", ret, "ret");
	push_back_format(v, "0x%x", lpBuffers->len, "len");

	Log(v, (wchar_t*)lpBuffers->buf, lpBuffers->len, "buf");
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
	///////////////////////////////////////////////
	OutputDebugString(TEXT("WSASendTo"));
	///////////////////////////////////////////////
	ret = ((PFMyWSASendTo)OrgWinAPI[9])(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpTo, iToLen, lpOverlapped, lpCompletionRoutine);

	SOCKADDR_IN* sock = (SOCKADDR_IN*)lpTo;
	vector<pair<string, string>> v;
	v.push_back({ "api", "WSASendTo" });
	push_back_format(v, "0x%x", s, "socket");
	push_back_format(v, "%d", ntohs(sock->sin_port), "port");
	v.push_back({ "ip", inet_ntoa(sock->sin_addr) });
	push_back_format(v, "0x%x", ret, "ret");
	push_back_format(v, "0x%x", lpBuffers->len, "len");

	Log(v, (wchar_t*)lpBuffers->buf, lpBuffers->len, "buf"); 
	return ret;
}
int WSAAPI Myclosesocket(SOCKET s) {
	int ret;
	///////////////////////////////////////////////
	OutputDebugString(TEXT("closesocket"));
	///////////////////////////////////////////////
	ret = ((PFMyclosesocket)OrgWinAPI[10])(s);

	vector<pair<string, string>> v;
	v.push_back({ "api", "closesocket" });
	push_back_format(v, "0x%x", s, "socket");
	push_back_format(v, "0x%x", ret, "ret");

	Log(v);

	return ret;
}
int WSAAPI MyWSAConnect(
	SOCKET         s,
	const sockaddr* name,
	int            namelen,
	LPWSABUF       lpCallerData,
	LPWSABUF       lpCalleeData,
	LPQOS          lpSQOS,
	LPQOS          lpGQOS
) {
	int ret;

	ret = ((PFMyWSAConnect)OrgWinAPI[11])(s, name, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS);
	SOCKADDR_IN* sock = (SOCKADDR_IN*)name;
	///////////////////////////////////////////////
	wchar_t buf[100];
	_stprintf(buf, L"WSAConnect, socket : %x, port : %d, ip : %s", s, ntohs(sock->sin_port), ConvertMultibyteToUnicode(inet_ntoa(sock->sin_addr)));
	if (ret == SOCKET_ERROR)
		lstrcat(buf, L" try to connect but failed");
	else
		lstrcat(buf, L" connect success");
	OutputDebugStringW(buf);
	OutputDebugStringA("WSAConnect");
	///////////////////////////////////////////////

	vector<pair<string, string>> v;
	v.push_back({ "api", "WSAConnect" });
	push_back_format(v, "0x%x", s, "socket");
	push_back_format(v, "%d", ntohs(sock->sin_port), "port");
	v.push_back({ "ip", inet_ntoa(sock->sin_addr) });
	if (ret == SOCKET_ERROR)
		v.push_back({ "Status", "Fail" });
	else
		v.push_back({ "Status", "Success" });

	Log(v);

	return ret;
}
/*
BOOL WINAPI MyCloseHandle(HANDLE hObject) {
	int ret;
	///////////////////////////////////////////////
	wchar_t buf[100];
	_stprintf(buf, L"MyCloseHandle, handle : %x, ", hObject);
	OutputDebugString(buf);
	///////////////////////////////////////////////
	ret = ((PFMyCloseHandle)OrgWinAPI[12])(hObject);

	if (SearchRemoveHandle(hObject)) {
		vector<pair<string, string>> v;
		v.push_back({ "api", "CloseHandle" });
		push_back_format(v, "0x%x", hObject, "HANDLE");
		push_back_format(v, "0x%x", ret, "ret");

		Log(v);
	}
	return ret;
}*/
SC_HANDLE WINAPI MyOpenServiceA(
	SC_HANDLE hSCManager,
	LPCTSTR lpServiceName, 
	DWORD dwDesiredAccess
) {
	SC_HANDLE ret;
	ret = ((PFMyOpenServiceA)OrgWinAPI[12])(hSCManager, lpServiceName, dwDesiredAccess);

	vector<pair<string, string>> v;
	v.push_back({ "api", "OpenServiceA" });
	push_back_format(v, "0x%x", hSCManager, "Handle");
	push_back_format(v, "0x%x", ret, "ret");
	v.push_back({ "ServiceName", (LPSTR)lpServiceName });
	push_back_format(v, "0x%x", dwDesiredAccess, "DesiredAccess");

	Log(v);

	return ret;
}
SC_HANDLE WINAPI MyOpenServiceW(
	SC_HANDLE hSCManager,
	LPWSTR lpServiceName,
	DWORD dwDesiredAccess
) {
	SC_HANDLE ret;
	ret = ((PFMyOpenServiceA)OrgWinAPI[13])(hSCManager, lpServiceName, dwDesiredAccess);

	vector<pair<string, string>> v;
	v.push_back({ "api", "OpenServiceW" });
	push_back_format(v, "0x%x", hSCManager, "Handle");
	push_back_format(v, "0x%x", ret, "ret");
	
	v.push_back({ "ServiceName", ConvertUnicodeToMultibyte(lpServiceName) });
	push_back_format(v, "0x%x", dwDesiredAccess, "DesiredAccess");

	Log(v);

	return ret;
}
SC_HANDLE WINAPI MyCreateServiceA(
	SC_HANDLE hSCManager,
	LPCSTR lpServiceName,
	LPCSTR lpDisplayName,
	DWORD dwDesiredAccess,
	DWORD dwServiceType,
	DWORD dwStartType,
	DWORD dwErrorControl,
	LPCSTR lpBinaryPathName,
	LPCSTR lpLoadOrderGroup,
	LPDWORD lpdwTagId,
	LPCSTR lpDependencies,
	LPCSTR lpServiceStartName,
	LPCSTR lpPassword
) {
	SC_HANDLE ret;
	ret = ((PFMyCreateServiceA)OrgWinAPI[14])(hSCManager, lpServiceName, lpDisplayName, dwDesiredAccess, dwServiceType, dwStartType, dwErrorControl, lpBinaryPathName, lpLoadOrderGroup, lpdwTagId, lpDependencies, lpServiceStartName, lpPassword);

	vector<pair<string, string>> v;
	v.push_back({ "api", "CreateServiceA" });
	push_back_format(v, "0x%x", hSCManager, "Handle");
	push_back_format(v, "0x%x", ret, "ret");

	v.push_back({ "ServiceName", lpServiceName });
	v.push_back({ "DisplayName", lpDisplayName });
	v.push_back({ "BinaryPathName", lpBinaryPathName });
	v.push_back({ "ServiceStartName", lpServiceStartName });
	v.push_back({ "Password", lpPassword });

	push_back_format(v, "0x%x", dwDesiredAccess, "DesiredAccess");
	push_back_format(v, "0x%x", dwServiceType, "ServiceType");
	push_back_format(v, "0x%x", dwStartType, "StartType");

	Log(v);

	return ret;
}
SC_HANDLE WINAPI MyCreateServiceW(
	SC_HANDLE hSCManager,
	LPCWSTR lpServiceName,
	LPCWSTR lpDisplayName,
	DWORD dwDesiredAccess,
	DWORD dwServiceType,
	DWORD dwStartType,
	DWORD dwErrorControl,
	LPCWSTR lpBinaryPathName,
	LPCWSTR lpLoadOrderGroup,
	LPDWORD lpdwTagId,
	LPCWSTR lpDependencies,
	LPCWSTR lpServiceStartName,
	LPCWSTR lpPassword
) {
	SC_HANDLE ret;
	ret = ((PFMyCreateServiceW)OrgWinAPI[15])(hSCManager, lpServiceName, lpDisplayName, dwDesiredAccess, dwServiceType, dwStartType, dwErrorControl, lpBinaryPathName, lpLoadOrderGroup, lpdwTagId, lpDependencies, lpServiceStartName, lpPassword);

	vector<pair<string, string>> v;
	v.push_back({ "api", "CreateServiceW" });
	push_back_format(v, "0x%x", hSCManager, "Handle");
	push_back_format(v, "0x%x", ret, "ret");
	
	v.push_back({ "ServiceName", ConvertUnicodeToMultibyte((LPWSTR)lpServiceName) });
	v.push_back({ "DisplayName", ConvertUnicodeToMultibyte((LPWSTR)lpDisplayName) });
	v.push_back({ "BinaryPathName", ConvertUnicodeToMultibyte((LPWSTR)lpBinaryPathName) });
	v.push_back({ "ServiceStartName", ConvertUnicodeToMultibyte((LPWSTR)lpServiceStartName) });
	v.push_back({ "Password", ConvertUnicodeToMultibyte((LPWSTR)lpPassword) });

	push_back_format(v, "0x%x", dwDesiredAccess, "DesiredAccess");
	push_back_format(v, "0x%x", dwServiceType, "ServiceType");
	push_back_format(v, "0x%x", dwStartType, "StartType");

	Log(v);

	return ret;
}
BOOL WINAPI MyStartServiceA(
	SC_HANDLE hService, 
	DWORD dwNumServiceArgs, 
	LPCTSTR* lpServiceArgVectors
) {
	BOOL ret;
	ret = ((PFMyStartServiceA)OrgWinAPI[16])(hService, dwNumServiceArgs, lpServiceArgVectors);

	vector<pair<string, string>> v;
	v.push_back({ "api", "StartServiceA" });
	push_back_format(v, "0x%x", hService, "Handle");
	push_back_format(v, "0x%x", ret, "ret");

	push_back_format(v, "0x%x", dwNumServiceArgs, "NumServiceArgs");

	Log(v);

	return ret;
}
BOOL WINAPI MyStartServiceW(
	SC_HANDLE hService,
	DWORD dwNumServiceArgs,
	LPCWSTR* lpServiceArgVectors
) {
	BOOL ret;
	ret = ((PFMyStartServiceW)OrgWinAPI[17])(hService, dwNumServiceArgs, lpServiceArgVectors);

	vector<pair<string, string>> v;
	v.push_back({ "api", "StartServiceW" });
	push_back_format(v, "0x%x", hService, "Handle");
	push_back_format(v, "0x%x", ret, "ret");

	push_back_format(v, "0x%x", dwNumServiceArgs, "NumServiceArgs");

	Log(v);

	return ret;
}
BOOL WINAPI MyControlService(
	SC_HANDLE hService, 
	DWORD dwControl, 
	LPSERVICE_STATUS lpServiceStatus
) {
	BOOL ret;
	ret = ((PFMyControlService)OrgWinAPI[18])(hService, dwControl, lpServiceStatus);

	vector<pair<string, string>> v;
	v.push_back({ "api", "ControlService" });
	push_back_format(v, "0x%x", hService, "Handle");
	push_back_format(v, "0x%x", ret, "ret");

	push_back_format(v, "0x%x", dwControl, "ControlCode");

	Log(v);

	return ret;
}
BOOL WINAPI MyDeleteService(
	SC_HANDLE hService
) {
	BOOL ret;
	ret = ((PFMyDeleteService)OrgWinAPI[19])(hService);

	vector<pair<string, string>> v;
	v.push_back({ "api", "DeleteService" });
	push_back_format(v, "0x%x", hService, "Handle");
	push_back_format(v, "0x%x", ret, "ret");

	Log(v);

	return ret;
}
HRESULT WINAPI MyURLDownloadToFileA(
	LPUNKNOWN pCaller,
	LPCSTR szURL, 
	LPCSTR szFileName,
	DWORD dwReserved, 
	LPBINDSTATUSCALLBACK lpfnCB
) {
	HRESULT ret;
	ret = ((PFMyURLDownloadToFileA)OrgWinAPI[20])(pCaller, szURL, szFileName, dwReserved, lpfnCB);

	vector<pair<string, string>> v;
	v.push_back({ "api", "URLDownloadToFileA" });
	v.push_back({ "URL", szURL });
	v.push_back({ "FileName", szFileName });
	push_back_format(v, "0x%x", ret, "ret");

	Log(v);

	return ret;
}
HRESULT WINAPI MyURLDownloadToFileW(
	LPUNKNOWN pCaller,
	LPCWSTR szURL,
	LPCWSTR szFileName,
	DWORD dwReserved,
	LPBINDSTATUSCALLBACK lpfnCB
) {
	HRESULT ret;
	ret = ((PFMyURLDownloadToFileW)OrgWinAPI[21])(pCaller, szURL, szFileName, dwReserved, lpfnCB);

	vector<pair<string, string>> v;
	v.push_back({ "api", "URLDownloadToFileA" });
	v.push_back({ "URL", ConvertUnicodeToMultibyte((LPWSTR)szURL) });
	v.push_back({ "FileName", ConvertUnicodeToMultibyte((LPWSTR)szFileName) });
	push_back_format(v, "0x%x", ret, "ret");

	Log(v);

	return ret;
}
BOOL WINAPI MyInternetReadFile(
	HINTERNET hFile,
	LPVOID lpBuffer,
	DWORD dwNumberOfBytesToRead,
	LPDWORD lpdwNumberOfBytesRead
) {
	BOOL ret;
	ret = ((PFMyInternetReadFile)OrgWinAPI[22])(hFile, lpBuffer, dwNumberOfBytesToRead, lpdwNumberOfBytesRead);

	vector<pair<string, string>> v;
	v.push_back({ "api", "InternetReadFile" });
	push_back_format(v, "0x%x", hFile, "hFile");
	push_back_format(v, "0x%x", ret, "ret");

	Log(v, (wchar_t*)lpBuffer, *lpdwNumberOfBytesRead, "buf");

	return ret;
}
BOOL WINAPI MyInternetWriteFile(
	HINTERNET hFile,
	LPCVOID lpBuffer,
	DWORD dwNumberOfBytesToWrite,
	LPDWORD lpdwNumberOfBytesWritten
) {
	BOOL ret;
	ret = ((PFMyInternetWriteFile)OrgWinAPI[23])(hFile, lpBuffer, dwNumberOfBytesToWrite, lpdwNumberOfBytesWritten);

	vector<pair<string, string>> v;
	v.push_back({ "api", "InternetWriteFile" });
	push_back_format(v, "0x%x", hFile, "hFile");
	push_back_format(v, "0x%x", ret, "ret");

	Log(v, (wchar_t*)lpBuffer, *lpdwNumberOfBytesWritten, "buf");

	return ret;
}
HINTERNET WINAPI MyInternetOpenA(
	LPCSTR lpszAgent,
	DWORD dwAccessType, 
	LPCSTR lpszProxy, 
	LPCSTR lpszProxyBypass, 
	DWORD dwFlags
) {
	HINTERNET ret;
	ret = ((PFMyInternetOpenA)OrgWinAPI[24])(lpszAgent, dwAccessType, lpszProxy, lpszProxyBypass, dwFlags);

	vector<pair<string, string>> v;
	v.push_back({ "api", "InternetOpenA" });
	v.push_back({ "Agent",lpszAgent });
	push_back_format(v, "0x%x", ret, "ret");

	Log(v);

	return ret;
}
HINTERNET WINAPI MyInternetOpenW(
	LPCWSTR lpszAgent,
	DWORD dwAccessType, 
	LPCWSTR lpszProxy,
	LPCWSTR lpszProxyBypass,
	DWORD dwFlags
){
	HINTERNET ret;
	ret = ((PFMyInternetOpenW)OrgWinAPI[25])(lpszAgent, dwAccessType, lpszProxy, lpszProxyBypass, dwFlags);

	vector<pair<string, string>> v;
	
	v.push_back({ "api", "InternetOpenW" });
	v.push_back({ "Agent",ConvertUnicodeToMultibyte((LPWSTR)lpszAgent) });
	push_back_format(v, "0x%x", ret, "ret");

	Log(v);

	return ret;
}
HINTERNET WINAPI MyInternetConnectA(
	HINTERNET hInternet,
	LPCSTR lpszServerName,
	INTERNET_PORT nServerPort,
	LPCSTR lpszUserName,
	LPCSTR lpszPassword,
	DWORD dwService,
	DWORD dwFlags,
	DWORD_PTR dwContext
) {
	HINTERNET ret;
	ret = ((PFMyInternetConnectA)OrgWinAPI[26])(hInternet, lpszServerName, nServerPort, lpszUserName, lpszPassword, dwService, dwFlags, dwContext);

	vector<pair<string, string>> v;

	v.push_back({ "api", "InternetConnectA" });
	push_back_format(v, "0x%x", hInternet, "hInternet");
	v.push_back({ "ServerName", lpszServerName });
	push_back_format(v, "0x%x", nServerPort, "ServerPort");
	v.push_back({ "UserName", lpszUserName });
	v.push_back({ "Password", lpszPassword });
	push_back_format(v, "0x%x", dwService, "Service");

	push_back_format(v, "0x%x", ret, "ret");

	Log(v);

	return ret;
}
HINTERNET WINAPI MyInternetConnectW(
	HINTERNET hInternet,
	LPCWSTR lpszServerName,
	INTERNET_PORT nServerPort,
	LPCWSTR lpszUserName,
	LPCWSTR lpszPassword,
	DWORD dwService,
	DWORD dwFlags,
	DWORD_PTR dwContext
) {
	HINTERNET ret;
	ret = ((PFMyInternetConnectW)OrgWinAPI[27])(hInternet, lpszServerName, nServerPort, lpszUserName, lpszPassword, dwService, dwFlags, dwContext);

	vector<pair<string, string>> v;
	
	v.push_back({ "api", "InternetConnectW" });
	push_back_format(v, "0x%x", hInternet, "hInternet");
	v.push_back({ "ServerName", ConvertUnicodeToMultibyte((LPWSTR)lpszServerName) });
	push_back_format(v, "0x%x", nServerPort, "ServerPort");
	v.push_back({ "UserName", ConvertUnicodeToMultibyte((LPWSTR)lpszUserName) });
	v.push_back({ "Password", ConvertUnicodeToMultibyte((LPWSTR)lpszPassword) });
	push_back_format(v, "0x%x", dwService, "Service");

	push_back_format(v, "0x%x", ret, "ret");

	Log(v);

	return ret;
}
HINTERNET WINAPI MyInternetOpenUrlA(
	HINTERNET hInternet,
	LPCSTR lpszUrl,
	LPCSTR lpszHeaders,
	DWORD dwHeadersLength,
	DWORD dwFlags,
	DWORD_PTR dwContext
) {
	HINTERNET ret;
	ret = ((PFMyInternetOpenUrlA)OrgWinAPI[28])(hInternet, lpszUrl, lpszHeaders, dwHeadersLength, dwFlags, dwContext);

	vector<pair<string, string>> v;

	v.push_back({ "api", "InternetOpenUrlA" });
	push_back_format(v, "0x%x", hInternet, "hInternet");
	v.push_back({ "URL", lpszUrl });
	push_back_format(v, "0x%x", ret, "ret");

	if (dwHeadersLength == (DWORD)-1) 
		dwHeadersLength = strlen(lpszHeaders);

	Log(v, (wchar_t*)lpszHeaders, dwHeadersLength, "Header");

	return ret;
}
HINTERNET WINAPI MyInternetOpenUrlW(
	HINTERNET hInternet,
	LPCWSTR lpszUrl,
	LPCWSTR lpszHeaders,
	DWORD dwHeadersLength,
	DWORD dwFlags,
	DWORD_PTR dwContext
) {
	HINTERNET ret;
	ret = ((PFMyInternetOpenUrlW)OrgWinAPI[29])(hInternet, lpszUrl, lpszHeaders, dwHeadersLength, dwFlags, dwContext);

	vector<pair<string, string>> v;

	v.push_back({ "api", "InternetOpenUrlW" });
	push_back_format(v, "0x%x", hInternet, "hInternet");
	v.push_back({ "URL", ConvertUnicodeToMultibyte((LPWSTR)lpszUrl) });
	push_back_format(v, "0x%x", ret, "ret");

	if (dwHeadersLength == (DWORD)-1)
		dwHeadersLength = lstrlen(lpszHeaders);

	Log(v, (wchar_t*)lpszHeaders, dwHeadersLength, "Header");

	return ret;
}
HINTERNET WINAPI MyHttpOpenRequestA(
	HINTERNET hConnect,
	LPCSTR lpszVerb,
	LPCSTR lpszObjectName,
	LPCSTR lpszVersion,
	LPCSTR lpszReferrer,
	LPCSTR* lplpszAcceptTypes,
	DWORD dwFlags,
	DWORD_PTR dwContext
) {
	HINTERNET ret;
	ret = ((PFMyHttpOpenRequestA)OrgWinAPI[30])(hConnect, lpszVerb, lpszObjectName, lpszVersion, lpszReferrer, lplpszAcceptTypes, dwFlags, dwContext);

	vector<pair<string, string>> v;

	v.push_back({ "api", "HttpOpenRequestA" });
	push_back_format(v, "0x%x", hConnect, "hConnect");
	v.push_back({ "ObjectName", lpszObjectName });
	push_back_format(v, "0x%x", ret, "ret");

	Log(v);

	return ret;
}
HINTERNET WINAPI MyHttpOpenRequestW(
	HINTERNET hConnect,
	LPCWSTR lpszVerb,
	LPCWSTR lpszObjectName,
	LPCWSTR lpszVersion,
	LPCWSTR lpszReferrer,
	LPCWSTR* lplpszAcceptTypes,
	DWORD dwFlags,
	DWORD_PTR dwContext
) {
	HINTERNET ret;
	ret = ((PFMyHttpOpenRequestW)OrgWinAPI[31])(hConnect, lpszVerb, lpszObjectName, lpszVersion, lpszReferrer, lplpszAcceptTypes, dwFlags, dwContext);

	vector<pair<string, string>> v;

	v.push_back({ "api", "HttpOpenRequestW" });
	push_back_format(v, "0x%x", hConnect, "hConnect");
	v.push_back({ "ObjectName", ConvertUnicodeToMultibyte((LPWSTR)lpszObjectName) });
	push_back_format(v, "0x%x", ret, "ret");

	Log(v);

	return ret;
}
BOOL WINAPI MyHttpSendRequestA(
	HINTERNET hRequest,
	LPCSTR lpszHeaders,
	DWORD dwHeadersLength,
	LPVOID lpOptional,
	DWORD dwOptionalLength
) {
	BOOL ret;
	ret = ((PFMyHttpSendRequestA)OrgWinAPI[32])(hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength);

	vector<pair<string, string>> v;

	v.push_back({ "api", "HttpSendRequestA" });
	push_back_format(v, "0x%x", hRequest, "hRequest");
	v.push_back({ "Header", lpszHeaders });
	v.push_back({ "Optional", (LPCSTR)lpOptional });
	push_back_format(v, "0x%x", ret, "ret");

	Log(v);

	return ret;
}
BOOL WINAPI MyHttpSendRequestW(
	HINTERNET hRequest,
	LPCWSTR lpszHeaders,
	DWORD dwHeadersLength,
	LPVOID lpOptional,
	DWORD dwOptionalLength
) {
	BOOL ret;
	ret = ((PFMyHttpSendRequestW)OrgWinAPI[33])(hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength);

	vector<pair<string, string>> v;
	
	v.push_back({ "api", "HttpSendRequestW" });
	push_back_format(v, "0x%x", hRequest, "hRequest");
	v.push_back({ "Header", ConvertUnicodeToMultibyte((LPWSTR)lpszHeaders) });
	v.push_back({ "Optional", ConvertUnicodeToMultibyte((LPWSTR)lpOptional) });
	push_back_format(v, "0x%x", ret, "ret");

	Log(v);

	return ret;
}
LPFN_CONNECTEX Org_Connectex;
int WSAAPI MyWSAIoctl(
	SOCKET s,
	DWORD dwIoControlCode,
	LPVOID lpvInBuffer,
	DWORD cbInBuffer,
	LPVOID lpvOutBuffer,
	DWORD cbOutBuffer,
	LPDWORD lpcbBytesReturned,
	LPWSAOVERLAPPED lpOverlapped,
	LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
) {
	BOOL ret;
	GUID ConnectExGUID = WSAID_CONNECTEX;
	ret = ((PFMyWSAIoctl)OrgWinAPI[34])(s, dwIoControlCode, lpvInBuffer, cbInBuffer, lpvOutBuffer, cbOutBuffer, lpcbBytesReturned, lpOverlapped, lpCompletionRoutine);
	if (dwIoControlCode == SIO_GET_EXTENSION_FUNCTION_POINTER && (*(GUID*)lpvInBuffer) == ConnectExGUID) {//guid도 같이 체크해야함.
		*(DWORD*)lpvOutBuffer = (DWORD)MyConnectex;
	}
	OutputDebugString(TEXT("WSAIoctl"));

	return ret;
}
BOOL WSAAPI MyConnectex(
	SOCKET s,
	const sockaddr* name,
	int namelen,
	PVOID lpSendBuffer,
	DWORD dwSendDataLength,
	LPDWORD lpdwBytesSent,
	LPOVERLAPPED lpOverlapped
) {
	BOOL ret;

	ret = ((PFMyConnectex)Org_Connectex)(s, name, namelen, lpSendBuffer, dwSendDataLength, lpdwBytesSent, lpOverlapped);
	SOCKADDR_IN* sock = (SOCKADDR_IN*)name;
	///////////////////////////////////////////////
	wchar_t buf[100];
	_stprintf(buf, L"connectex, socket : %x, port : %d, ip : %s", s, ntohs(sock->sin_port), ConvertMultibyteToUnicode(inet_ntoa(sock->sin_addr)));
	if (ret == SOCKET_ERROR)
		lstrcat(buf, L" try to connect but failed");
	else
		lstrcat(buf, L" connect success");
	OutputDebugStringW(buf);
	OutputDebugStringA("ConnectEx");
	///////////////////////////////////////////////


	vector<pair<string, string>> v;
	v.push_back({ "api", "ConnectEx" });
	push_back_format(v, "0x%x", s, "socket");
	push_back_format(v, "%d", ntohs(sock->sin_port), "port");
	v.push_back({ "ip", inet_ntoa(sock->sin_addr) });
	if (ret == SOCKET_ERROR)
		v.push_back({ "Status", "Fail" });
	else
		v.push_back({ "Status", "Success" });

	Log(v);

	return ret;
}
LSTATUS WINAPI MyRegCreateKeyA(
	HKEY hKey,
	LPCSTR lpSubKey,
	PHKEY phkResult
) {
	LSTATUS ret = ((PFMyRegCreateKeyA)OrgWinAPI[35])(hKey, lpSubKey, phkResult);

	vector<pair<string, string>> v;
	v.push_back({ "api", "RegCreateKeyA" });
	push_back_format(v, "0x%x", *phkResult, "KeyHandle");
	push_back_format(v, "0x%x", hKey, "HIVE");
	v.push_back({ "lpSubKey", lpSubKey });
	push_back_format(v, "0x%x", ret, "ret");

	Log(v);
	return ret;
}
LSTATUS WINAPI MyRegCreateKeyW(
	HKEY hKey,
	LPCWSTR lpSubKey,
	PHKEY phkResult
) {
	LSTATUS ret = ((PFMyRegCreateKeyW)OrgWinAPI[36])(hKey, lpSubKey, phkResult);

	vector<pair<string, string>> v;
	v.push_back({ "api", "RegCreateKeyW" });
	push_back_format(v, "0x%x", *phkResult, "KeyHandle");
	push_back_format(v, "0x%x", hKey, "HIVE");
	v.push_back({ "lpSubKey", ConvertUnicodeToMultibyte((LPWSTR)lpSubKey) });
	push_back_format(v, "0x%x", ret, "ret");

	Log(v);
	return ret;
}
LSTATUS WINAPI MyRegCreateKeyExA(
	HKEY hKey,
	LPCSTR lpSubKey,
	DWORD Reserved,
	LPSTR lpClass,
	DWORD dwOptions,
	REGSAM samDesired,
	const LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	PHKEY phkResult,
	LPDWORD lpdwDisposition
) {
	LSTATUS ret = ((PFMyRegCreateKeyExA)OrgWinAPI[37])(hKey, lpSubKey, Reserved, lpClass, dwOptions, samDesired, lpSecurityAttributes, phkResult, lpdwDisposition);

	vector<pair<string, string>> v;
	v.push_back({ "api", "RegCreateKeyExA" });
	push_back_format(v, "0x%x", *phkResult, "KeyHandle");
	push_back_format(v, "0x%x", hKey, "HIVE");
	v.push_back({ "lpSubKey", lpSubKey });
	push_back_format(v, "0x%x", *lpdwDisposition, "lpdwDisposition");
	push_back_format(v, "0x%x", ret, "ret");

	Log(v);
	return ret;
}
LSTATUS WINAPI MyRegCreateKeyExW(
	HKEY hKey,
	LPCWSTR lpSubKey,
	DWORD Reserved,
	LPWSTR lpClass,
	DWORD dwOptions,
	REGSAM samDesired,
	const LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	PHKEY phkResult,
	LPDWORD lpdwDisposition
) {
	LSTATUS ret = ((PFMyRegCreateKeyExW)OrgWinAPI[38])(hKey, lpSubKey, Reserved, lpClass, dwOptions, samDesired, lpSecurityAttributes, phkResult, lpdwDisposition);

	vector<pair<string, string>> v;
	v.push_back({ "api", "RegCreateKeyExW" });
	push_back_format(v, "0x%x", *phkResult, "KeyHandle");
	push_back_format(v, "0x%x", hKey, "HIVE");
	v.push_back({ "lpSubKey", ConvertUnicodeToMultibyte((LPWSTR)lpSubKey) });
	push_back_format(v, "0x%x", *lpdwDisposition, "lpdwDisposition");
	push_back_format(v, "0x%x", ret, "ret");

	Log(v);
	return ret;
}
LSTATUS WINAPI MyRegOpenKeyA(
	HKEY hKey,
	LPCSTR lpSubKey,
	PHKEY phkResult
) {
	LSTATUS ret = ((PFMyRegOpenKeyA)OrgWinAPI[39])(hKey, lpSubKey, phkResult);

	vector<pair<string, string>> v;
	v.push_back({ "api", "RegOpenKeyA" });
	push_back_format(v, "0x%x", *phkResult, "KeyHandle");
	push_back_format(v, "0x%x", hKey, "HIVE");
	v.push_back({ "lpSubKey", lpSubKey });
	push_back_format(v, "0x%x", ret, "ret");

	Log(v);
	return ret;
}
LSTATUS WINAPI MyRegOpenKeyW(
	HKEY hKey,
	LPCWSTR lpSubKey,
	PHKEY phkResult
) {
	LSTATUS ret = ((PFMyRegOpenKeyW)OrgWinAPI[40])(hKey, lpSubKey, phkResult);

	vector<pair<string, string>> v;
	v.push_back({ "api", "RegOpenKeyW" });
	push_back_format(v, "0x%x", *phkResult, "KeyHandle");
	push_back_format(v, "0x%x", hKey, "HIVE");
	v.push_back({ "lpSubKey", ConvertUnicodeToMultibyte((LPWSTR)lpSubKey) });
	push_back_format(v, "0x%x", ret, "ret");

	Log(v);
	return ret;
}
LSTATUS WINAPI MyRegOpenKeyExA(
	HKEY hKey,
	LPCSTR lpSubKey,
	DWORD ulOptions,
	REGSAM samDesired,
	PHKEY phkResult
) {
	LSTATUS ret = ((PFMyRegOpenKeyExA)OrgWinAPI[41])(hKey, lpSubKey, ulOptions, samDesired, phkResult);

	vector<pair<string, string>> v;
	v.push_back({ "api", "RegOpenKeyExA" });
	push_back_format(v, "0x%x", *phkResult, "KeyHandle");
	push_back_format(v, "0x%x", hKey, "HIVE");
	v.push_back({ "lpSubKey", lpSubKey });
	push_back_format(v, "0x%x", ret, "ret");

	Log(v);
	return ret;
}
LSTATUS WINAPI MyRegOpenKeyExW(
	HKEY hKey,
	LPCWSTR lpSubKey,
	DWORD ulOptions,
	REGSAM samDesired,
	PHKEY phkResult
) {
	LSTATUS ret = ((PFMyRegOpenKeyExW)OrgWinAPI[42])(hKey, lpSubKey, ulOptions, samDesired, phkResult);

	vector<pair<string, string>> v;
	v.push_back({ "api", "RegOpenKeyExW" });
	push_back_format(v, "0x%x", *phkResult, "KeyHandle");
	push_back_format(v, "0x%x", hKey, "HIVE");
	v.push_back({ "lpSubKey", ConvertUnicodeToMultibyte((LPWSTR)lpSubKey) });
	push_back_format(v, "0x%x", ret, "ret");

	Log(v);
	return ret;
}
LSTATUS WINAPI MyRegSetValueA(
	HKEY hKey,
	LPCSTR lpSubKey,
	DWORD dwType,
	LPCSTR lpData,
	DWORD cbData
) {
	LSTATUS ret = ((PFMyRegSetValueA)OrgWinAPI[43])(hKey, lpSubKey, dwType, lpData, cbData);

	vector<pair<string, string>> v;
	v.push_back({ "api", "RegSetValueA" });
	push_back_format(v, "0x%x", hKey, "KeyHandle");
	v.push_back({ "lpSubKey", lpSubKey });
	push_back_format(v, "0x%x", dwType, "dwType");
	push_back_format(v, "0x%x", ret, "ret");

	Log(v);
	Log(v, (wchar_t*)lpData, cbData, "Data");
	return ret;
}
LSTATUS WINAPI MyRegSetValueW(
	HKEY hKey,
	LPCWSTR lpSubKey,
	DWORD dwType,
	LPCWSTR lpData,
	DWORD cbData
) {
	LSTATUS ret = ((PFMyRegSetValueW)OrgWinAPI[44])(hKey, lpSubKey, dwType, lpData, cbData);

	vector<pair<string, string>> v;
	v.push_back({ "api", "RegSetValueW" });
	push_back_format(v, "0x%x", hKey, "KeyHandle");
	v.push_back({ "lpSubKey", ConvertUnicodeToMultibyte((LPWSTR)lpSubKey) });
	push_back_format(v, "0x%x", dwType, "dwType");
	push_back_format(v, "0x%x", ret, "ret");

	Log(v, (wchar_t*)lpData, cbData, "Data");
	return ret;
}
LSTATUS WINAPI MyRegSetValueExA(
	HKEY hKey,
	LPCSTR lpValueName,
	DWORD Reserved,
	DWORD dwType,
	const BYTE* lpData,
	DWORD cbData
) {
	LSTATUS ret = ((PFMyRegSetValueExA)OrgWinAPI[45])(hKey, lpValueName, Reserved, dwType, lpData, cbData);

	vector<pair<string, string>> v;
	v.push_back({ "api", "RegSetValueExA" });
	push_back_format(v, "0x%x", hKey, "KeyHandle");
	v.push_back({ "lpValueName", lpValueName });
	push_back_format(v, "0x%x", dwType, "dwType");
	push_back_format(v, "0x%x", ret, "ret");

	Log(v, (wchar_t*)lpData, cbData, "Data");
	return ret;
}
LSTATUS WINAPI MyRegSetValueExW(
	HKEY hKey,
	LPCWSTR lpValueName,
	DWORD Reserved,
	DWORD dwType,
	const BYTE* lpData,
	DWORD cbData
) {
	LSTATUS ret = ((PFMyRegSetValueExW)OrgWinAPI[46])(hKey, lpValueName, Reserved, dwType, lpData, cbData);

	vector<pair<string, string>> v;
	v.push_back({ "api", "RegSetValueExW" });
	push_back_format(v, "0x%x", hKey, "KeyHandle");
	v.push_back({ "lpValueName", ConvertUnicodeToMultibyte((LPWSTR)lpValueName) });
	push_back_format(v, "0x%x", dwType, "dwType");
	push_back_format(v, "0x%x", ret, "ret");

	Log(v, (wchar_t*)lpData, cbData, "Data");
	return ret;
}
LSTATUS WINAPI MyRegSetKeyValueA(
	HKEY hKey,
	LPCSTR lpSubKey,
	LPCSTR lpValueName,
	DWORD dwType,
	LPCVOID lpData,
	DWORD cbData
) {
	LSTATUS ret = ((PFMyRegSetKeyValueA)OrgWinAPI[47])(hKey, lpSubKey, lpValueName, dwType, lpData, cbData);

	vector<pair<string, string>> v;
	v.push_back({ "api", "RegSetKeyValueA" });
	push_back_format(v, "0x%x", hKey, "KeyHandle");
	v.push_back({ "lpSubKey", lpSubKey });
	v.push_back({ "lpValueName", lpValueName });
	push_back_format(v, "0x%x", dwType, "dwType");
	push_back_format(v, "0x%x", ret, "ret");

	Log(v, (wchar_t*)lpData, cbData, "Data");
	return ret;
}
LSTATUS WINAPI MyRegSetKeyValueW(
	HKEY hKey,
	LPCWSTR lpSubKey,
	LPCWSTR lpValueName,
	DWORD dwType,
	LPCVOID lpData,
	DWORD cbData
) {
	LSTATUS ret = ((PFMyRegSetKeyValueW)OrgWinAPI[48])(hKey, lpSubKey, lpValueName, dwType, lpData, cbData);

	vector<pair<string, string>> v;
	v.push_back({ "api", "RegSetKeyValueW" });
	push_back_format(v, "0x%x", hKey, "KeyHandle");
	v.push_back({ "lpSubKey", ConvertUnicodeToMultibyte((LPWSTR)lpSubKey) });
	v.push_back({ "lpValueName", ConvertUnicodeToMultibyte((LPWSTR)lpValueName) });
	push_back_format(v, "0x%x", dwType, "dwType");
	push_back_format(v, "0x%x", ret, "ret");

	Log(v, (wchar_t*)lpData, cbData, "Data");
	return ret;
}
LSTATUS WINAPI MyRegDeleteKeyA(
	HKEY hKey,
	LPCSTR lpSubKey
) {
	LSTATUS ret = ((PFMyRegDeleteKeyA)OrgWinAPI[49])(hKey, lpSubKey);

	vector<pair<string, string>> v;
	v.push_back({ "api", "RegDeleteKeyA" });
	push_back_format(v, "0x%x", hKey, "KeyHandle");
	v.push_back({ "lpSubKey", lpSubKey });
	push_back_format(v, "0x%x", ret, "ret");

	Log(v);
	return ret;
}
LSTATUS WINAPI MyRegDeleteKeyW(
	HKEY hKey,
	LPCWSTR lpSubKey
) {
	LSTATUS ret = ((PFMyRegDeleteKeyW)OrgWinAPI[50])(hKey, lpSubKey);

	vector<pair<string, string>> v;
	v.push_back({ "api", "RegDeleteKeyW" });
	push_back_format(v, "0x%x", hKey, "KeyHandle");
	v.push_back({ "lpSubKey", ConvertUnicodeToMultibyte((LPWSTR)lpSubKey) });
	push_back_format(v, "0x%x", ret, "ret");

	Log(v);
	return ret;
}
LSTATUS WINAPI MyRegDeleteKeyExA(
	HKEY hKey,
	LPCSTR lpSubKey,
	REGSAM samDesired,
	DWORD Reserved
) {
	LSTATUS ret = ((PFMyRegDeleteKeyExA)OrgWinAPI[51])(hKey, lpSubKey, samDesired, Reserved);

	vector<pair<string, string>> v;
	v.push_back({ "api", "RegDeleteKeyExA" });
	push_back_format(v, "0x%x", hKey, "KeyHandle");
	v.push_back({ "lpSubKey", lpSubKey });
	push_back_format(v, "0x%x", ret, "ret");

	Log(v);
	return ret;
}
LSTATUS WINAPI MyRegDeleteKeyExW(
	HKEY hKey,
	LPCWSTR lpSubKey,
	REGSAM samDesired,
	DWORD Reserved
) {
	LSTATUS ret = ((PFMyRegDeleteKeyExW)OrgWinAPI[52])(hKey, lpSubKey, samDesired, Reserved);

	vector<pair<string, string>> v;
	v.push_back({ "api", "RegDeleteKeyExW" });
	push_back_format(v, "0x%x", hKey, "KeyHandle");
	v.push_back({ "lpSubKey", ConvertUnicodeToMultibyte((LPWSTR)lpSubKey) });
	push_back_format(v, "0x%x", ret, "ret");

	Log(v);
	return ret;
}
LSTATUS WINAPI MyRegDeleteValueA(
	HKEY hKey,
	LPCSTR lpValueName
) {
	LSTATUS ret = ((PFMyRegDeleteValueA)OrgWinAPI[53])(hKey, lpValueName);

	vector<pair<string, string>> v;
	v.push_back({ "api", "RegDeleteValueA" });
	push_back_format(v, "0x%x", hKey, "KeyHandle");
	v.push_back({ "lpValueName", lpValueName });
	push_back_format(v, "0x%x", ret, "ret");

	Log(v);
	return ret;
}
LSTATUS WINAPI MyRegDeleteValueW(
	HKEY hKey,
	LPCWSTR lpValueName
) {
	LSTATUS ret = ((PFMyRegDeleteValueW)OrgWinAPI[54])(hKey, lpValueName);

	vector<pair<string, string>> v;
	v.push_back({ "api", "RegDeleteValueW" });
	push_back_format(v, "0x%x", hKey, "KeyHandle");
	v.push_back({ "lpValueName", ConvertUnicodeToMultibyte((LPWSTR)lpValueName) });
	push_back_format(v, "0x%x", ret, "ret");

	Log(v);
	return ret;
}
LSTATUS WINAPI MyRegDeleteKeyValueA(
	HKEY hKey,
	LPCSTR lpSubKey,
	LPCSTR lpValueName
) {
	LSTATUS ret = ((PFMyRegDeleteKeyValueA)OrgWinAPI[55])(hKey, lpSubKey, lpValueName);

	vector<pair<string, string>> v;
	v.push_back({ "api", "RegDeleteKeyValueA" });
	push_back_format(v, "0x%x", hKey, "KeyHandle");
	v.push_back({ "lpSubKey", lpSubKey });
	v.push_back({ "lpValueName", lpValueName });
	push_back_format(v, "0x%x", ret, "ret");

	Log(v);
	return ret;
}
LSTATUS WINAPI MyRegDeleteKeyValueW(
	HKEY hKey,
	LPCWSTR lpSubKey,
	LPCWSTR lpValueName
) {
	LSTATUS ret = ((PFMyRegDeleteKeyValueW)OrgWinAPI[56])(hKey, lpSubKey, lpValueName);

	vector<pair<string, string>> v;
	v.push_back({ "api", "RegDeleteKeyValueW" });
	push_back_format(v, "0x%x", hKey, "KeyHandle");
	v.push_back({ "lpSubKey", ConvertUnicodeToMultibyte((LPWSTR)lpSubKey) });
	v.push_back({ "lpValueName", ConvertUnicodeToMultibyte((LPWSTR)lpValueName) });
	push_back_format(v, "0x%x", ret, "ret");

	Log(v);
	return ret;
}
LSTATUS WINAPI MyRegCloseKey(
	HKEY hKey
) {
	LSTATUS ret = ((PFMyRegCloseKey)OrgWinAPI[57])(hKey);

	vector<pair<string, string>> v;
	v.push_back({ "api", "RegCloseKey" });
	push_back_format(v, "0x%x", hKey, "KeyHandle");
	push_back_format(v, "0x%x", ret, "ret");

	Log(v);
	return ret;
}
BOOL WINAPI MyCloseServiceHandle(
	SC_HANDLE hSCObject
) {
	BOOL ret = ((PFMyCloseServiceHandle)OrgWinAPI[58])(hSCObject);

	vector<pair<string, string>> v;
	v.push_back({ "api", "CloseServiceHandle" });
	push_back_format(v, "0x%x", hSCObject, "Handle");
	push_back_format(v, "0x%x", ret, "ret");

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
	MyWSARecv,
	MyWSARecvFrom,
	MyWSASend, 
	MyWSASendTo,
	Myclosesocket,
	MyWSAConnect,
	MyOpenServiceA,
	MyOpenServiceW,
	MyCreateServiceA,
	MyCreateServiceW,
	MyStartServiceA,
	MyStartServiceW,
	MyControlService,
	MyDeleteService,
	MyURLDownloadToFileA,
	MyURLDownloadToFileW,
	MyInternetReadFile,
	MyInternetWriteFile,
	MyInternetOpenA,
	MyInternetOpenW,
	MyInternetConnectA,
	MyInternetConnectW,
	MyInternetOpenUrlA,
	MyInternetOpenUrlW,
	MyHttpOpenRequestA,
	MyHttpOpenRequestW,
	MyHttpSendRequestA,
	MyHttpSendRequestW,
	MyWSAIoctl,
	MyRegCreateKeyA,
	MyRegCreateKeyW,
	MyRegCreateKeyExA,
	MyRegCreateKeyExW,
	MyRegOpenKeyA,
	MyRegOpenKeyW,
	MyRegOpenKeyExA,
	MyRegOpenKeyExW,
	MyRegSetValueA,
	MyRegSetValueW,
	MyRegSetValueExA,
	MyRegSetValueExW,
	MyRegSetKeyValueA,
	MyRegSetKeyValueW,
	MyRegDeleteKeyA,
	MyRegDeleteKeyW,
	MyRegDeleteKeyExA,
	MyRegDeleteKeyExW,
	MyRegDeleteValueA,
	MyRegDeleteValueW,
	MyRegDeleteKeyValueA,
	MyRegDeleteKeyValueW,
	MyRegCloseKey,
	MyCloseServiceHandle
};