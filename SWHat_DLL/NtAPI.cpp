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
typedef NTSTATUS(NTAPI* PFMyNtCreateUserProcess)(PHANDLE ProcessHandle, PHANDLE ThreadHandle, ACCESS_MASK ProcessDesiredAccess, ACCESS_MASK ThreadDesiredAccess, POBJECT_ATTRIBUTES ProcessObjectAttributes, POBJECT_ATTRIBUTES ThreadObjectAttributes, ULONG ProcessFlags, ULONG ThreadFlags, PRTL_USER_PROCESS_PARAMETERS ProcessParameters, PPS_CREATE_INFO CreateInfo, PPS_ATTRIBUTE_LIST AttributeList);
typedef NTSTATUS(NTAPI* PFMyNtWriteVirtualMemory)(HANDLE ProcessHandle, LPVOID BaseAddress, LPCVOID Buffer, ULONG NumberOfBytesToWrite, ULONG* NumberOfBytesWritten);
typedef NTSTATUS(NTAPI* PFMyNtClose)(HANDLE Handle);

BOOL ExceptNtCreateFile(LPWSTR fileName) {
#define EXACTNUM 2
#define PARTIALNUM 5
	BOOL ret = FALSE, flag;
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
				ret = TRUE;
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
			ret = TRUE;
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

	if (hLogFile == *FileHandle)
		return ret;
	
	if (!ExceptNtCreateFile(ObjectAttributes->ObjectName->Buffer)) {
		PUNICODE_STRING str = ObjectAttributes->ObjectName;
		BOOL is_full = FALSE;
		char current_directory[MAX_PATH];
		for (int i = 0; i < lstrlen(str->Buffer); i++) {
			if (str->Buffer[i] == ':') {
				is_full = TRUE;
				break;
			}
		}
		if (*FileHandle) {
			vector<pair<string, string>> v;
			v.push_back({ "api", "NtCreateFile" });
			if (is_full) {
				v.push_back({ "FileName", string(ConvertUnicodeToMultibyte(str->Buffer)) });
			}
			else {
				GetCurrentDirectoryA(MAX_PATH, current_directory);
				v.push_back({ "FileName", string(current_directory) + " " + string(ConvertUnicodeToMultibyte(str->Buffer)) });
			}
			push_back_format(v, "0x%x", ret, "ret");
			push_back_format(v, "0x%x", *FileHandle, "FileHandle");
			push_back_format(v, "0x%x", DesiredAccess, "AccessMask");

			InsertHandle(*FileHandle);

			Log(v);
		}
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

	NTSTATUS ret = ((PFMyNtWriteFile)OrgNTAPI[1])(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);
	
	if (hLogFile == FileHandle)return ret;

	///////////////////////////////////////////////
	char buf[1000];//큰거 들어오면 터짐
	sprintf(buf, "FileHandle : %x, ", FileHandle);
	strcat(buf, "NtWriteFile");
	OutputDebugStringA(buf);
	///////////////////////////////////////////////

	vector<pair<string, string>> v;
	v.push_back({ "api", "NtWriteFile" });
	push_back_format(v, "0x%x", FileHandle, "FileHandle");
	push_back_format(v, "0x%x", ret, "ret");
	push_back_format(v, "0x%x", Length, "Length");
	

	Log(v, (wchar_t*)Buffer, Length, "Buffer");

	return ret;
}
BOOL isInjection;
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
	isInjection = TRUE;
	WriteProcessMemory(hProcess, pRemoteBuf, (LPVOID)szDllPath, dwBufSize, NULL);
	hModule = GetModuleHandle(TEXT("kernel32.dll"));
	pThreadproc = (LPTHREAD_START_ROUTINE)GetProcAddress(hModule, "LoadLibraryW");
	isInjection = TRUE;
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
	NTSTATUS ret = ((PFMyNtCreateUserProcess)OrgNTAPI[2])(ProcessHandle, ThreadHandle, ProcessDesiredAccess, ThreadDesiredAccess, ProcessObjectAttributes, ThreadObjectAttributes, ProcessFlags, 1, ProcessParameters, CreateInfo, AttributeList);

	//InjectDll(TEXT("C:\\Users\\tmdahr1245\\source\\repos\\SWHat_DLL\\Release\\SWHat_DLL.dll"), GetProcessId(*ProcessHandle));
	InjectDll(TEXT(".\\SWHat_DLL.dll"), GetProcessId(*ProcessHandle));
	if (!ThreadFlags)ResumeThread(*ThreadHandle);

	if (*ProcessHandle) {
		vector<pair<string, string>> v;
		v.push_back({ "api", "NtCreateUserProcess" });
		push_back_format(v, "0x%x", *ProcessHandle, "ProcessHandle");
		push_back_format(v, "%d", GetProcessId(*ProcessHandle), "pid");
		v.push_back({ "ImagePathName", string(ConvertUnicodeToMultibyte(ProcessParameters->ImagePathName.Buffer)) });
		v.push_back({ "cmdline", string(ConvertUnicodeToMultibyte(ProcessParameters->CommandLine.Buffer)) });
		push_back_format(v, "0x%x", ret, "ret");

		InsertHandle(*ProcessHandle);
		Log(v);
	}

	return ret;
}
NTSTATUS NTAPI MyNtWriteVirtualMemory(//createuserprocess안 injectdll에서 호출되는 writeprocessmemory일경우 예외처리 해줘야함
	HANDLE ProcessHandle,
	LPVOID BaseAddress,
	LPCVOID Buffer,
	ULONG NumberOfBytesToWrite,
	ULONG* NumberOfBytesWritten
) {
	NTSTATUS ret = ((PFMyNtWriteVirtualMemory)OrgNTAPI[3])(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);

	if (!isInjection) {
		vector<pair<string, string>> v;
		v.push_back({ "api", "NtWriteVirtualMemory" });
		push_back_format(v, "0x%x", ProcessHandle, "ProcessHandle");
		push_back_format(v, "%d", GetProcessId(ProcessHandle), "pid");
		push_back_format(v, "0x%x", BaseAddress, "BaseAddress");
		push_back_format(v, "0x%x", ret, "ret");
		push_back_format(v, "0x%x", NumberOfBytesToWrite, "NumberOfBytesToWrite");

		Log(v, (wchar_t*)Buffer, NumberOfBytesToWrite, "Buffer");
		isInjection = FALSE;
	}
	return ret;
}

NTSTATUS NTAPI MyNtClose(
	HANDLE Handle
) {
	NTSTATUS ret = ((PFMyNtClose)OrgNTAPI[4])(Handle);

	if (SearchRemoveHandle(Handle)) {
		vector<pair<string, string>> v;
		v.push_back({ "api", "NtClose" });
		push_back_format(v, "0x%x", Handle, "Handle");
		push_back_format(v, "0x%x", ret, "ret");

		Log(v);
	}
	return ret;
}
LPVOID MyNtFunc[NTAPI_NUM] = { 
	MyNtCreateFile, 
	MyNtWriteFile, 
	MyNtCreateUserProcess,
	MyNtWriteVirtualMemory,
	MyNtClose,
};
