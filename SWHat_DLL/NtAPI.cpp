#include "NtAPI.hpp"
#include "Log.hpp"
#include "Util.hpp"
#include <tchar.h>
#include <stdio.h>
#include <iostream>
#include <vector>
using namespace std;

#define BUFSIZE 1000
#pragma warning(disable: 4996)

LPVOID OrgNTAPI[NTAPI_NUM] = { 0, };

//Function Pointer Definition
typedef NTSTATUS(NTAPI* PFMyNtCreateFile)(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize OPTIONAL, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer OPTIONAL, ULONG EaLength);
typedef NTSTATUS(NTAPI* PFMyNtWriteFile)(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key);
typedef NTSTATUS(NTAPI* PFMyNtDeleteKey)(HANDLE KeyHandle);
typedef NTSTATUS(NTAPI* PFMyNtDeleteValueKey)(HANDLE KeyHandle, PUNICODE_STRING ValueName);
typedef NTSTATUS(NTAPI* PFMyNtCreateKey)(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, ULONG TitleIndex, PUNICODE_STRING Class, ULONG CreateOptions, PULONG Disposition);
typedef NTSTATUS(NTAPI* PFMyNtOpenKey)(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);
typedef NTSTATUS(NTAPI* PFMyNtSetValueKey)(HANDLE KeyHandle, PUNICODE_STRING ValueName, ULONG TitleIndex, ULONG Type, PVOID Data, ULONG DataSize);
typedef NTSTATUS(NTAPI* PFMyNtCreateUserProcess)(PHANDLE ProcessHandle, PHANDLE ThreadHandle, ACCESS_MASK ProcessDesiredAccess, ACCESS_MASK ThreadDesiredAccess, POBJECT_ATTRIBUTES ProcessObjectAttributes, POBJECT_ATTRIBUTES ThreadObjectAttributes, ULONG ProcessFlags, ULONG ThreadFlags, PRTL_USER_PROCESS_PARAMETERS ProcessParameters, PPS_CREATE_INFO CreateInfo, PPS_ATTRIBUTE_LIST AttributeList);
typedef NTSTATUS(NTAPI* PFMyNtWriteVirtualMemory)(HANDLE ProcessHandle, LPVOID BaseAddress, LPCVOID Buffer, ULONG NumberOfBytesToWrite, ULONG* NumberOfBytesWritten);
typedef NTSTATUS(NTAPI* PFMyNtClose)(HANDLE Handle);

BOOL ExceptNtCreateFile(LPWSTR fileName) {
#define EXACTNUM 2
#define PARTIALNUM 5
	BOOL ret = TRUE, flag;
	DWORD file_len = lstrlen(fileName);
	wchar_t exact_match[EXACTNUM][50] = {
		TEXT("\\??\\PIPE\\lsarpc"),
		TEXT("\\??\\MountPointManager")
	};
	wchar_t partial_match[PARTIALNUM][50] = {
		TEXT("\\??\\IDE#"),
		TEXT("\\??\\STORAGE#"),
		TEXT("\\??\\root#"),
		TEXT("\\Device\\"),
		TEXT("\\??\\Nsi")
	};
	for (int i = 0; i < EXACTNUM; i++) {
		int len = lstrlen(exact_match[i]);
		flag = TRUE;
		if (len == file_len) {
			for (int j = 0; j < len; j++) {
				if (fileName[j] == exact_match[i][j])
					continue;
				else {
					flag = FALSE;
					break;
				}
			}
			if (flag) {
				ret = FALSE;
				break;
			}
		}
	}
	for (int i = 0; i < PARTIALNUM; i++) {
		flag = TRUE;
		for (int j = 0; j < lstrlen(partial_match[i]); j++) {
			if (j == file_len)break;
			if (fileName[j] == partial_match[i][j]) {
				continue;
			}
			else {
				flag = FALSE;
				break;
			}
		}
		if (flag) {
			ret = FALSE;
			break;
		}
	}
	return ret;
}
NTSTATUS NTAPI MyNtCreateFile(
	PHANDLE FileHandle, 
	ACCESS_MASK DesiredAccess, //0x40000000L -> 쓰기권한
	POBJECT_ATTRIBUTES ObjectAttributes, 
	PIO_STATUS_BLOCK IoStatusBlock, 
	PLARGE_INTEGER AllocationSize OPTIONAL, 
	ULONG FileAttributes, 
	ULONG ShareAccess, 
	ULONG CreateDisposition, 
	ULONG CreateOptions, 
	PVOID EaBuffer OPTIONAL, 
	ULONG EaLength
) {
	
	NTSTATUS ret = ((PFMyNtCreateFile)OrgNTAPI[0])(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
	//if (lstrcmp(ObjectAttributes->ObjectName->Buffer, L"test.json")!=0) {
	//	return ret;
	//}
	if (hLogFile == *FileHandle)
		return ret;

	//if ((ObjectAttributes->ObjectName->Buffer[0] == 't' &&
	//	ObjectAttributes->ObjectName->Buffer[1] == 'e' &&
	//	ObjectAttributes->ObjectName->Buffer[2] == 's' &&
	//	ObjectAttributes->ObjectName->Buffer[3] == 't')){
	/*if(check(ObjectAttributes->ObjectName->Buffer)){
		if(!hLogFile)
			hLogFile = *FileHandle;
		return ret;
	}*/
	
	if (ExceptNtCreateFile(ObjectAttributes->ObjectName->Buffer)) {
		//GetCurrentDirectoryA(1000, dir);
		PUNICODE_STRING str = ObjectAttributes->ObjectName;

		str->Buffer;
		wchar_t buf[1000];
		wchar_t tmp[1000];
		wchar_t* file_name;
		BOOL is_full = FALSE;
		lstrcpy(buf, TEXT("NtCreateFile "));
		//절대경로인지 상대경로인지 체크해주는데 notepad에서 터짐
		//알고리즘 다시 생각해야함
		/**/
		for (int i = 0; i < lstrlen(str->Buffer);i++) {
			if (str->Buffer[i] == ':') {
				is_full = TRUE;
				break;
			}
		}
		if (!is_full) {//상대경로일경우 인자로 들어온 파일명과 경로 출력
			GetCurrentDirectoryW(1000, tmp);
			lstrcat(buf, tmp);
			lstrcat(buf, L" ");
			lstrcat(buf, str->Buffer);
		}
		else {//절대경로일경우 파일명 그대로 출력
			lstrcat(buf, str->Buffer);
		}
		//file_name = (wchar_t*)malloc(sizeof(wchar_t) * lstrlen(str->Buffer));
		//lstrcpy(file_name, str->Buffer);
		/*if (*file_name == '.'){
			lstrcpy(file_name, file_name + 1);
			file_name--;
		}
		if (*file_name == '\\') {
			lstrcpy(file_name, file_name + 1);
			file_name--;
		}
		if (*file_name == '/') {
			lstrcpy(file_name, file_name + 1);
			file_name--;
		}*//**/
		//lstrcat(buf, L"\\");
		//lstrcat(buf, str->Buffer);
		lstrcat(buf, TEXT(", ret : "));
		wsprintf(tmp, TEXT("%x"), ret);
		lstrcat(buf, tmp);

		lstrcat(buf, TEXT(", FileHandle : "));
		wsprintf(tmp, TEXT("%x"), *FileHandle);
		lstrcat(buf, tmp);

		lstrcat(buf, TEXT(", access_mask : "));
		wsprintf(tmp, TEXT("%x"), DesiredAccess);
		lstrcat(buf, tmp);

		lstrcat(buf, TEXT(", FileAttributes : "));
		wsprintf(tmp, TEXT("%x"), FileAttributes);
		lstrcat(buf, tmp);

		lstrcat(buf, TEXT(", CreateDisposition : "));
		wsprintf(tmp, TEXT("%x"), CreateDisposition);
		lstrcat(buf, tmp);

		lstrcat(buf, TEXT(", CreateOptions : "));
		wsprintf(tmp, TEXT("%x"), CreateOptions);
		lstrcat(buf, tmp);

		OutputDebugString(buf);
		vector<pair<string, pair<string, string>>> v;
		v.emplace_back(make_pair("string", make_pair("api", "NtCreateFile")));
		v.emplace_back(make_pair("string", make_pair("FileName", string(ConvertUnicodeToMultibyte(str->Buffer)))));
		char tt[100];
		sprintf(tt, "0x%x", ret);
		v.emplace_back(make_pair("int", make_pair("ret", tt)));
		sprintf(tt, "0x%x", *FileHandle);
		v.emplace_back(make_pair("int", make_pair("FileHandle", tt)));
		sprintf(tt, "0x%x", DesiredAccess);
		v.emplace_back(make_pair("int", make_pair("AcessMask", tt)));


		//Log();
		Log(v);

	}
	return ret;
}
NTSTATUS NTAPI MyNtWriteFile(
	HANDLE FileHandle, 
	HANDLE Event, 
	PIO_APC_ROUTINE ApcRoutine, 
	PVOID ApcContext, 
	PIO_STATUS_BLOCK IoStatusBlock, 
	PVOID Buffer, 
	ULONG Length, 
	PLARGE_INTEGER ByteOffset, 
	PULONG Key
) {
	BOOL is_Bypass = TRUE;
	if (hLogFile != FileHandle)is_Bypass = FALSE;
	NTSTATUS ret = ((PFMyNtWriteFile)OrgNTAPI[1])(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);
	if (is_Bypass) {
		return ret;
	}
	char buf[1000];//큰거 들어오면 터짐
	sprintf(buf, "FileHandle : %x, ", FileHandle);
	strcat(buf, "NtWriteFile");
	//strcat(buf, (LPCSTR)Buffer);
	OutputDebugStringA(buf);
	//Log();
	wchar_t t[1000];
	_stprintf(t, L"NtWriteFile, FileHandle : %x", FileHandle);
	//Log2(t);
	vector<pair<string, pair<string, string>>> v;
	v.emplace_back(make_pair("string", make_pair("api", "NtWriteFile")));
	char tt[100];
	sprintf(tt, "0x%x", FileHandle);
	v.emplace_back(make_pair("int", make_pair("FileHandle", tt)));
	sprintf(tt, "0x%x", ret);
	v.emplace_back(make_pair("int", make_pair("ret", tt)));

	//Log2(v);
	LogWithBuffer(v, (wchar_t*)Buffer, Length, "Buffer");
	return ret;
}
NTSTATUS NTAPI MyNtDeleteKey(//ntopenkey로 handle가져오는데 ntopenkey로그에서 레지스트리명 얻으면 될듯
	HANDLE KeyHandle
) {
	NTSTATUS ret = ((PFMyNtDeleteKey)OrgNTAPI[2])(KeyHandle);
	wchar_t buf[1000];
	_stprintf(buf, L"MyNtDeleteKey, FileHandle : %x, ", KeyHandle);
	//strcat(buf, (LPCSTR)Buffer);
	OutputDebugString(buf);
	//Log2(buf);
	//OutputDebugString(TEXT("NtDeleteKey"));
	vector<pair<string, pair<string, string>>> v;
	v.emplace_back(make_pair("string", make_pair("api", "NtDeleteKey")));
	char tt[100];
	sprintf(tt, "0x%x", KeyHandle);
	v.emplace_back(make_pair("int", make_pair("KeyHandle", tt)));

	//Log();
	Log(v);
	return ret;
}
NTSTATUS NTAPI MyNtDeleteValueKey(//ntcreatekey로 handle 가져오는데 ntcreatekey 로그에서 레지스트리명 얻으면 될듯
	HANDLE KeyHandle, 
	PUNICODE_STRING ValueName
) {
	NTSTATUS ret = ((PFMyNtDeleteValueKey)OrgNTAPI[3])(KeyHandle, ValueName);
	wchar_t buf[1000];
	_stprintf(buf, L"MyNtDeleteValueKey, FileHandle : %x, ", KeyHandle);
	//strcat(buf, (LPCSTR)Buffer);
	OutputDebugStringW(buf);
	//Log2(buf);
	//OutputDebugString(TEXT("NtDeleteValueKey"));
	vector<pair<string, pair<string, string>>> v;
	v.emplace_back(make_pair("string", make_pair("api", "NtDeleteValueKey")));
	char tt[100];
	sprintf(tt, "0x%x", KeyHandle);
	v.emplace_back(make_pair("int", make_pair("KeyHandle", tt)));
	v.emplace_back(make_pair("string", make_pair("ValueName", string(ConvertUnicodeToMultibyte(ValueName->Buffer)))));
	sprintf(tt, "0x%x", ret);
	v.emplace_back(make_pair("int", make_pair("ret", tt)));

	//Log();
	Log(v);
	return ret;
}
NTSTATUS NTAPI MyNtCreateKey(
	PHANDLE KeyHandle, 
	ACCESS_MASK DesiredAccess, 
	POBJECT_ATTRIBUTES ObjectAttributes, 
	ULONG TitleIndex, 
	PUNICODE_STRING Class,
	ULONG CreateOptions, 
	PULONG Disposition
) {
	NTSTATUS ret = ((PFMyNtCreateKey)OrgNTAPI[4])(KeyHandle, DesiredAccess, ObjectAttributes, TitleIndex, Class, CreateOptions, Disposition);
	wchar_t buf[1000];
	_stprintf(buf, L"MyNtCreateKey, FileHandle : %x, Obj : %s", *KeyHandle, ObjectAttributes->ObjectName->Buffer);
	//strcat(buf, (LPCSTR)Buffer);
	OutputDebugStringW(buf);
	//Log2(buf);
	//OutputDebugString(TEXT("NtCreateKey"));
	vector<pair<string, pair<string, string>>> v;
	v.emplace_back(make_pair("string", make_pair("api", "NtCreateKey")));
	char tt[100];
	sprintf(tt, "0x%x", *KeyHandle);
	v.emplace_back(make_pair("int", make_pair("KeyHandle", tt)));
	//v.emplace_back(make_pair("string", make_pair("Class", string(ConvertUnicodeToMultibyte(Class->Buffer)))));//주석풀면 파일 저장할때 크래시 나던데..
	v.emplace_back(make_pair("string", make_pair("Name", string(ConvertUnicodeToMultibyte(ObjectAttributes->ObjectName->Buffer)))));
	sprintf(tt, "0x%x", ret);
	v.emplace_back(make_pair("int", make_pair("ret", tt)));

	//Log();
	Log(v);
	return ret;
}
NTSTATUS NTAPI MyNtOpenKey(
	PHANDLE KeyHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes
) {
	NTSTATUS ret = ((PFMyNtOpenKey)OrgNTAPI[5])(KeyHandle, DesiredAccess, ObjectAttributes);
	wchar_t buf[1000];
	_stprintf(buf, L"MyNtOpenKey, FileHandle : %x, Name(?) : %s", *KeyHandle, ObjectAttributes->ObjectName->Buffer);
	//strcat(buf, (LPCSTR)Buffer);
	OutputDebugStringW(buf);
	//OutputDebugString(TEXT("NtOpenKey"));
	//Log2(buf);
	vector<pair<string, pair<string, string>>> v;
	v.emplace_back(make_pair("string", make_pair("api", "NtOpenKey")));
	char tt[100];
	sprintf(tt, "0x%x", *KeyHandle);
	v.emplace_back(make_pair("int", make_pair("KeyHandle", tt)));
	v.emplace_back(make_pair("string", make_pair("Name", string(ConvertUnicodeToMultibyte(ObjectAttributes->ObjectName->Buffer)))));
	sprintf(tt, "0x%x", ret);
	v.emplace_back(make_pair("int", make_pair("ret", tt)));
	Log(v);
	return ret;
}
NTSTATUS NTAPI MyNtSetValueKey(
	HANDLE KeyHandle, 
	PUNICODE_STRING ValueName, 
	ULONG TitleIndex, 
	ULONG Type, 
	PVOID Data, 
	ULONG DataSize
) {
	NTSTATUS ret = ((PFMyNtSetValueKey)OrgNTAPI[6])(KeyHandle, ValueName, TitleIndex, Type, Data, DataSize);
	wchar_t buf[1000];
	_stprintf(buf, L"MyNtSetValueKey, FileHandle : %x, Value : %s", KeyHandle, ValueName->Buffer);
	//strcat(buf, (LPCSTR)Buffer);
	OutputDebugStringW(buf);
	//Log2(buf);
	//OutputDebugString(TEXT("NtSetValueKey"));
	vector<pair<string, pair<string, string>>> v;
	v.emplace_back(make_pair("string", make_pair("api", "NtSetValueKey")));
	char tt[100];
	sprintf(tt, "0x%x", KeyHandle);
	v.emplace_back(make_pair("int", make_pair("KeyHandle", tt)));
	v.emplace_back(make_pair("string", make_pair("Value", string(ConvertUnicodeToMultibyte(ValueName->Buffer)))));
	sprintf(tt, "0x%x", ret);
	v.emplace_back(make_pair("int", make_pair("ret", tt)));
	LogWithBuffer(v, (wchar_t*)Data, DataSize, "Data");
	return ret;
}
BOOL InjectDll(LPCTSTR szDllPath, DWORD dwPID) {
	HANDLE hProcess = NULL, hThread = NULL;
	HMODULE hModule = NULL;
	LPVOID pRemoteBuf = NULL;
	DWORD dwBufSize = (DWORD)(_tcslen(szDllPath) + 1) * sizeof(TCHAR);
	LPTHREAD_START_ROUTINE pThreadproc;
	if (!(hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID))) {
		return FALSE;
	}
	pRemoteBuf = VirtualAllocEx(hProcess, NULL, dwBufSize, MEM_COMMIT, PAGE_READWRITE);
	WriteProcessMemory(hProcess, pRemoteBuf, (LPVOID)szDllPath, dwBufSize, NULL);
	hModule = GetModuleHandle(TEXT("kernel32.dll"));
	pThreadproc = (LPTHREAD_START_ROUTINE)GetProcAddress(hModule, "LoadLibraryW");
	hThread = CreateRemoteThread(hProcess, NULL, 0, pThreadproc, pRemoteBuf, 0, NULL);
	WaitForSingleObject(hThread, INFINITE);
	CloseHandle(hThread);
	CloseHandle(hProcess);
	return TRUE;
}
NTSTATUS NTAPI MyNtCreateUserProcess(
	PHANDLE ProcessHandle, 
	PHANDLE ThreadHandle, 
	ACCESS_MASK ProcessDesiredAccess,
	ACCESS_MASK ThreadDesiredAccess, 
	POBJECT_ATTRIBUTES ProcessObjectAttributes, //여기서 프로세스명 가져오려하면 터짐
	POBJECT_ATTRIBUTES ThreadObjectAttributes, 
	ULONG ProcessFlags, 
	ULONG ThreadFlags, //#define THREAD_CREATE_FLAGS_CREATE_SUSPENDED 1
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters, 
	PPS_CREATE_INFO CreateInfo, 
	PPS_ATTRIBUTE_LIST AttributeList
) {
	NTSTATUS ret = ((PFMyNtCreateUserProcess)OrgNTAPI[7])(ProcessHandle, ThreadHandle, ProcessDesiredAccess, ThreadDesiredAccess, ProcessObjectAttributes, ThreadObjectAttributes, ProcessFlags, 1/*ThreadFlags*/, ProcessParameters, CreateInfo, AttributeList);
	wchar_t buf[1000]; 
	wchar_t tmp[100];
	_stprintf(buf, TEXT("NtCreateUserProcess(pid : %d, "), GetProcessId(*ProcessHandle));
	lstrcat(buf, ProcessParameters->ImagePathName.Buffer);
	lstrcat(buf, TEXT(", cmdline : "));
	lstrcat(buf, ProcessParameters->CommandLine.Buffer);
	
	OutputDebugString(buf);
	//Log2(buf);
	InjectDll(TEXT("C:\\Users\\tmdahr1245\\source\\repos\\SWHat_DLL\\Release\\SWHat_DLL.dll"), GetProcessId(*ProcessHandle));
	if (!ThreadFlags)ResumeThread(ThreadHandle);
	vector<pair<string, pair<string, string>>> v;
	v.emplace_back(make_pair("string", make_pair("api", "NtCreateUserProcess")));
	char tt[100];
	sprintf(tt, "0x%x", *ProcessHandle);
	v.emplace_back(make_pair("int", make_pair("ProcessHandle", tt)));
	sprintf(tt, "%d", GetProcessId(*ProcessHandle));
	v.emplace_back(make_pair("int", make_pair("pid", tt)));
	v.emplace_back(make_pair("string", make_pair("ImagePathName", string(ConvertUnicodeToMultibyte(ProcessParameters->ImagePathName.Buffer)))));
	v.emplace_back(make_pair("string", make_pair("cmdline", string(ConvertUnicodeToMultibyte(ProcessParameters->CommandLine.Buffer)))));
	sprintf(tt, "0x%x", ret);
	v.emplace_back(make_pair("int", make_pair("ret", tt)));
	Log(v);

	return ret;
}
NTSTATUS NTAPI MyNtWriteVirtualMemory(//createuserprocess안 injectdll에서 호출되는 writeprocessmemory일경우 예외처리 해줘야함
	HANDLE ProcessHandle,
	LPVOID BaseAddress,
	LPCVOID Buffer,
	ULONG NumberOfBytesToWrite,
	ULONG* NumberOfBytesWritten
) {
	NTSTATUS ret = ((PFMyNtWriteVirtualMemory)OrgNTAPI[8])(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);
	wchar_t buf[100];
	_stprintf(buf, L"NtWriteVirtualMemory, pid : %d, ", GetProcessId(ProcessHandle));
	lstrcat(buf, L"");
	OutputDebugString(buf);
	//Log2(buf);
	//OutputDebugString(TEXT("NtWriteVirtualMemory"));
	vector<pair<string, pair<string, string>>> v;
	v.emplace_back(make_pair("string", make_pair("api", "NtWriteVirtualMemory")));
	char tt[100];
	sprintf(tt, "0x%x", ProcessHandle);
	v.emplace_back(make_pair("int", make_pair("ProcessHandle", tt)));
	sprintf(tt, "%d", GetProcessId(ProcessHandle));
	v.emplace_back(make_pair("int", make_pair("pid", tt)));
	sprintf(tt, "0x%x", BaseAddress);
	v.emplace_back(make_pair("int", make_pair("BaseAddress", tt)));
	sprintf(tt, "0x%x", ret);
	v.emplace_back(make_pair("int", make_pair("ret", tt)));
	LogWithBuffer(v, (wchar_t*)Buffer, NumberOfBytesToWrite, "Buffer");
	return ret;
}

NTSTATUS NTAPI MyNtClose(
	HANDLE Handle
) {
	wchar_t log[1000];
	DWORD dwBytes = 0;
	_stprintf(log, L"NtClose handle : %x", Handle);
	//Log2(log);
	//WriteFile(hLogFile, log, strlen(log), &dwBytes, NULL);
	NTSTATUS ret = ((PFMyNtClose)OrgNTAPI[9])(Handle);
	vector<pair<string, pair<string, string>>> v;
	v.emplace_back(make_pair("string", make_pair("api", "NtClose")));
	char tt[100];
	sprintf(tt, "0x%x", Handle);
	v.emplace_back(make_pair("int", make_pair("Handle", tt)));
	sprintf(tt, "0x%x", ret);
	v.emplace_back(make_pair("int", make_pair("ret", tt)));
	Log(v);
	return ret;
}
LPVOID MyNtFunc[NTAPI_NUM] = { 
	MyNtCreateFile, 
	MyNtWriteFile, 
	MyNtDeleteKey, 
	MyNtDeleteValueKey, 
	MyNtCreateKey, 
	MyNtOpenKey, 
	MyNtSetValueKey, 
	MyNtCreateUserProcess,
	MyNtWriteVirtualMemory,
	MyNtClose
};
