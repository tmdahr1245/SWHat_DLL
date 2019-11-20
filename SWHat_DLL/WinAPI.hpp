#include <stdio.h>
#include <wchar.h>
#include <winsock2.h>
#include <windows.h>
#include <winternl.h>
#include <Wininet.h>
#include <MSWSock.h>

#define WINAPI_NUM 11 + 8 + 14 + 1 + 2 + 23

extern LPVOID OrgWinAPI[WINAPI_NUM];
extern LPVOID MyFunc[WINAPI_NUM];
extern LPFN_CONNECTEX Org_Connectex;

//Socket
int WSAAPI Myconnect(SOCKET s, const sockaddr* name, int namelen);
int WSAAPI Mysend(SOCKET s, const char* buf, int len, int flags);
int WSAAPI Mysendto(SOCKET s, const char* buf, int len, DWORD flags, const struct sockaddr* to, int tolen);
int WSAAPI Myrecv(SOCKET s, char* buf, int len, int flags);
int WSAAPI Myrecvfrom(SOCKET s, char* buf, int len, int flags, struct sockaddr* from, int* fromlen);
SOCKET WSAAPI Myaccept(SOCKET s, struct sockaddr* addr, int* addrlen);
int WSAAPI MyWSARecv(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);
int WSAAPI MyWSARecvFrom(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags, struct sockaddr* lpFrom, LPINT lpFromlen, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);
int WSAAPI MyWSASend(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesSent, DWORD dwFlags, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);
int WSAAPI MyWSASendTo(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesSent, DWORD dwFlags, const struct sockaddr* lpTo, int iToLen, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);
int WSAAPI Myclosesocket(SOCKET s);
int WSAAPI MyWSAConnect(SOCKET s, const sockaddr* name, int namelen, LPWSABUF lpCallerData, LPWSABUF lpCalleeData, LPQOS lpSQOS, LPQOS lpGQOS);
int WSAAPI MyWSAIoctl(SOCKET s, DWORD dwIoControlCode, LPVOID lpvInBuffer, DWORD cbInBuffer, LPVOID lpvOutBuffer, DWORD cbOutBuffer, LPDWORD lpcbBytesReturned, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);
BOOL WSAAPI MyConnectex(SOCKET s, const sockaddr* name, int namelen, PVOID lpSendBuffer, DWORD dwSendDataLength, LPDWORD lpdwBytesSent, LPOVERLAPPED lpOverlapped);

//Service
SC_HANDLE WINAPI MyOpenServiceA(SC_HANDLE hSCManager, LPCTSTR lpServiceName, DWORD dwDesiredAccess);
SC_HANDLE WINAPI MyOpenServiceW(SC_HANDLE hSCManager, LPWSTR lpServiceName, DWORD dwDesiredAccess);
SC_HANDLE WINAPI MyCreateServiceA(SC_HANDLE hSCManager, LPCSTR lpServiceName, LPCSTR lpDisplayName, DWORD dwDesiredAccess, DWORD dwServiceType, DWORD dwStartType, DWORD dwErrorControl, LPCSTR lpBinaryPathName, LPCSTR lpLoadOrderGroup, LPDWORD lpdwTagId, LPCSTR lpDependencies, LPCSTR lpServiceStartName, LPCSTR lpPassword);
SC_HANDLE WINAPI MyCreateServiceW(SC_HANDLE hSCManager, LPCWSTR lpServiceName, LPCWSTR lpDisplayName, DWORD dwDesiredAccess, DWORD dwServiceType, DWORD dwStartType, DWORD dwErrorControl, LPCWSTR lpBinaryPathName, LPCWSTR lpLoadOrderGroup, LPDWORD lpdwTagId, LPCWSTR lpDependencies, LPCWSTR lpServiceStartName, LPCWSTR lpPassword);
BOOL WINAPI MyStartServiceA(SC_HANDLE hService, DWORD dwNumServiceArgs, LPCTSTR* lpServiceArgVectors);
BOOL WINAPI MyStartServiceW(SC_HANDLE hService, DWORD dwNumServiceArgs, LPCWSTR* lpServiceArgVectors);
BOOL WINAPI MyControlService(SC_HANDLE hService, DWORD dwControl, LPSERVICE_STATUS lpServiceStatus);
BOOL WINAPI MyDeleteService(SC_HANDLE hService);
BOOL WINAPI MyCloseServiceHandle(SC_HANDLE hSCObject);

//Network
HRESULT WINAPI MyURLDownloadToFileA(LPUNKNOWN pCaller, LPCSTR szURL, LPCSTR szFileName, DWORD dwReserved, LPBINDSTATUSCALLBACK lpfnCB);
HRESULT WINAPI MyURLDownloadToFileW(LPUNKNOWN pCaller, LPCWSTR szURL, LPCWSTR szFileName, DWORD dwReserved, LPBINDSTATUSCALLBACK lpfnCB);
BOOL WINAPI MyInternetReadFile(HINTERNET hFile, LPVOID lpBuffer, DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead);
BOOL WINAPI MyInternetWriteFile(HINTERNET hFile,	LPCVOID lpBuffer, DWORD dwNumberOfBytesToWrite, LPDWORD lpdwNumberOfBytesWritten);
HINTERNET WINAPI MyInternetOpenA(LPCSTR lpszAgent, DWORD dwAccessType, LPCSTR lpszProxy, LPCSTR lpszProxyBypass, DWORD dwFlags);
HINTERNET WINAPI MyInternetOpenW(LPCWSTR lpszAgent, DWORD dwAccessType, LPCWSTR lpszProxy, LPCWSTR lpszProxyBypass, DWORD dwFlags);
HINTERNET WINAPI MyInternetConnectA(HINTERNET hInternet, LPCSTR lpszServerName, INTERNET_PORT nServerPort, LPCSTR lpszUserName, LPCSTR lpszPassword, DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext);
HINTERNET WINAPI MyInternetConnectW(HINTERNET hInternet, LPCWSTR lpszServerName, INTERNET_PORT nServerPort, LPCWSTR lpszUserName, LPCWSTR lpszPassword, DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext);
HINTERNET WINAPI MyInternetOpenUrlA(HINTERNET hInternet, LPCSTR lpszUrl, LPCSTR lpszHeaders, DWORD dwHeadersLength, DWORD dwFlags, DWORD_PTR dwContext);
HINTERNET WINAPI MyInternetOpenUrlW(HINTERNET hInternet, LPCWSTR lpszUrl, LPCWSTR lpszHeaders, DWORD dwHeadersLength, DWORD dwFlags, DWORD_PTR dwContext);
HINTERNET WINAPI MyHttpOpenRequestA(HINTERNET hConnect, LPCSTR lpszVerb, LPCSTR lpszObjectName, LPCSTR lpszVersion, LPCSTR lpszReferrer, LPCSTR* lplpszAcceptTypes, DWORD dwFlags, DWORD_PTR dwContext);
HINTERNET WINAPI MyHttpOpenRequestW(HINTERNET hConnect, LPCWSTR lpszVerb, LPCWSTR lpszObjectName, LPCWSTR lpszVersion, LPCWSTR lpszReferrer, LPCWSTR* lplpszAcceptTypes, DWORD dwFlags, DWORD_PTR dwContext);
BOOL WINAPI MyHttpSendRequestA(HINTERNET hRequest, LPCSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength);
BOOL WINAPI MyHttpSendRequestW(HINTERNET hRequest, LPCWSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength);

//Registry
LSTATUS WINAPI MyRegCreateKeyA(HKEY hKey, LPCSTR lpSubKey, PHKEY phkResult);
LSTATUS WINAPI MyRegCreateKeyW(HKEY hKey, LPCWSTR lpSubKey, PHKEY phkResult);
LSTATUS WINAPI MyRegCreateKeyExA(HKEY hKey, LPCSTR lpSubKey, DWORD Reserved, LPSTR lpClass, DWORD dwOptions, REGSAM samDesired, const LPSECURITY_ATTRIBUTES lpSecurityAttributes, PHKEY phkResult, LPDWORD lpdwDisposition);
LSTATUS WINAPI MyRegCreateKeyExW(HKEY hKey, LPCWSTR lpSubKey, DWORD Reserved, LPWSTR lpClass, DWORD dwOptions, REGSAM samDesired, const LPSECURITY_ATTRIBUTES lpSecurityAttributes, PHKEY phkResult, LPDWORD lpdwDisposition);
LSTATUS WINAPI MyRegOpenKeyA(HKEY hKey, LPCSTR lpSubKey, PHKEY phkResult);
LSTATUS WINAPI MyRegOpenKeyW(HKEY hKey, LPCWSTR lpSubKey, PHKEY phkResult);
LSTATUS WINAPI MyRegOpenKeyExA(HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult);
LSTATUS WINAPI MyRegOpenKeyExW(HKEY hKey, LPCWSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult);
LSTATUS WINAPI MyRegSetValueA(HKEY hKey, LPCSTR lpSubKey, DWORD dwType, LPCSTR lpData, DWORD cbData);
LSTATUS WINAPI MyRegSetValueW(HKEY hKey, LPCWSTR lpSubKey, DWORD dwType, LPCWSTR lpData, DWORD cbData);
LSTATUS WINAPI MyRegSetValueExA(HKEY hKey, LPCSTR lpValueName, DWORD Reserved, DWORD dwType, const BYTE* lpData, DWORD cbData);
LSTATUS WINAPI MyRegSetValueExW(HKEY hKey, LPCWSTR lpValueName, DWORD Reserved, DWORD dwType, const BYTE* lpData, DWORD cbData);
LSTATUS WINAPI MyRegSetKeyValueA(HKEY hKey, LPCSTR lpSubKey, LPCSTR lpValueName, DWORD dwType, LPCVOID lpData, DWORD cbData);
LSTATUS WINAPI MyRegSetKeyValueW(HKEY hKey, LPCWSTR lpSubKey, LPCWSTR lpValueName, DWORD dwType, LPCVOID lpData, DWORD cbData);
LSTATUS WINAPI MyRegDeleteKeyA(HKEY hKey, LPCSTR lpSubKey);
LSTATUS WINAPI MyRegDeleteKeyW(HKEY hKey, LPCWSTR lpSubKey);
LSTATUS WINAPI MyRegDeleteKeyExA(HKEY hKey, LPCSTR lpSubKey, REGSAM samDesired, DWORD Reserved);
LSTATUS WINAPI MyRegDeleteKeyExW(HKEY hKey, LPCWSTR lpSubKey, REGSAM samDesired, DWORD Reserved);
LSTATUS WINAPI MyRegDeleteValueA(HKEY hKey, LPCSTR lpValueName);
LSTATUS WINAPI MyRegDeleteValueW(HKEY hKey, LPCWSTR lpValueName);
LSTATUS WINAPI MyRegDeleteKeyValueA(HKEY hKey, LPCSTR lpSubKey, LPCSTR lpValueName);
LSTATUS WINAPI MyRegDeleteKeyValueW(HKEY hKey, LPCWSTR lpSubKey, LPCWSTR lpValueName);
LSTATUS WINAPI MyRegCloseKey(HKEY hKey);
