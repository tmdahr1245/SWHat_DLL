
#include "WinAPI.hpp"
#include "NtAPI.hpp"
#include "Util.hpp"
#pragma warning(disable: 4996)

#define PE_SIGNATURE 0x3C
#define RVA_IAT 0x80
#define JMP_OPCODE 0xE9

typedef struct {
	char dll_list[WINAPI_NUM][50];
	char api_list[WINAPI_NUM][50];
	LPVOID function_list[WINAPI_NUM];
}WinAPI_struct;

typedef struct {
	char NTapi_list[NTAPI_NUM][50];
	LPVOID NTfunction_list[NTAPI_NUM];
}NTAPI_struct;


char Winapi_list[WINAPI_NUM][2][50] = {
	{"Ws2_32.dll","connect"},
	{"Ws2_32.dll","send"},
	{"Ws2_32.dll","sendto"},
	{"Ws2_32.dll","recv"},
	{"Ws2_32.dll","recvfrom"},
	{"Ws2_32.dll","accept"},
	{"Ws2_32.dll","connectEx"},
	{"Ws2_32.dll","TransmitFile"},
	{"Ws2_32.dll","WSARecv"},
	{"Ws2_32.dll","WSARecvFrom"},
	{"Ws2_32.dll","WSASend"},
	{"Ws2_32.dll","WSASendTo"},
	{"kernel32.dll","CloseHandle"}
};

char NTapi_list[NTAPI_NUM][50] = {
	"NtCreateFile",
	"NtWriteFile",
	"NtDeleteKey",
	"NtDeleteValueKey",
	"NtCreateKey",
	"NtOpenKey",
	"NtSetValueKey",
	"NtCreateUserProcess",
	"NtWriteVirtualMemory",
	"NtClose"
};
WinAPI_struct* winapi;
NTAPI_struct* ntapi;

VOID Init() {
	winapi = (WinAPI_struct*)malloc(sizeof(WinAPI_struct));
	if (!winapi) {
		OutputDebugString(TEXT("WinAPI Malloc Error"));
	}
	ntapi = (NTAPI_struct*)malloc(sizeof(NTAPI_struct));
	if (!ntapi) {
		OutputDebugString(TEXT("WinAPI Malloc Error"));
	}
	for (int i = 0; i < WINAPI_NUM; i++) {
		strcpy(winapi->dll_list[i], Winapi_list[i][0]);
		strcpy(winapi->api_list[i], Winapi_list[i][1]);
		winapi->function_list[i] = MyFunc[i];
	}
	for (int i = 0; i < NTAPI_NUM; i++) {
		strcpy(ntapi->NTapi_list[i], NTapi_list[i]);
		ntapi->NTfunction_list[i] = MyNtFunc[i];
	}
}

BOOL hook_iat(LPCSTR szDllName, PROC pfnOrg, PROC pfnNew, DWORD idx) {
	HMODULE hMod;
	LPCSTR szLibName;
	PIMAGE_IMPORT_DESCRIPTOR pImportDesc;
	PIMAGE_THUNK_DATA pThunk;
	DWORD dwOldProtect, dwRVA;
	PBYTE pAddr;
	OrgWinAPI[idx] = pfnOrg;
	hMod = GetModuleHandle(NULL);
	if (!hMod) {
		OutputDebugString(TEXT("GetModuleHandle Error"));
		return  FALSE;
	}
	pAddr = (PBYTE)hMod;
	pAddr += *((DWORD*)& pAddr[PE_SIGNATURE]);
	dwRVA = *((DWORD*)& pAddr[RVA_IAT]);
	pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)hMod + dwRVA);
	
	//DLL Search
	for (; pImportDesc->Name; pImportDesc++) {
		szLibName = (LPCSTR)((DWORD)hMod + pImportDesc->Name);
		if (!_stricmp(szLibName, szDllName)) {
			pThunk = (PIMAGE_THUNK_DATA)((DWORD)hMod + pImportDesc->FirstThunk);
			//API Search
			for (; pThunk->u1.Function; pThunk++) {
				if (pThunk->u1.Function == (DWORD)pfnOrg) {
					VirtualProtect((LPVOID)& pThunk->u1.Function, 4, PAGE_EXECUTE_READWRITE, &dwOldProtect);
					pThunk->u1.Function = (DWORD)pfnNew;
					VirtualProtect((LPVOID)& pThunk->u1.Function, 4, dwOldProtect, &dwOldProtect);
					return TRUE;
				}
			}
		}
	}
	return FALSE;
}
BOOL hook_code(LPCSTR szDllName, LPCSTR szFuncName, PROC pfnNew, DWORD idx) {
	FARPROC pFunc;
	DWORD dwOldProtect, dwAddress;
	BYTE pBuf[5] = { JMP_OPCODE, 0, };
	PBYTE pByte;
	BYTE calc_byte[10] = { 0, };

	pFunc = (FARPROC)GetProcAddress(GetModuleHandleA(szDllName), szFuncName);

	if (!pFunc) {
		OutputDebugString(TEXT("GetProcAddress Error"));
		return  FALSE;
	}
	pByte = (PBYTE)pFunc;
	if (pByte[0] == JMP_OPCODE)
		return FALSE;

	memcpy(calc_byte, pFunc, 5);
	calc_byte[5] = JMP_OPCODE;

	LPVOID hook_byte = VirtualAlloc(NULL, 10, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	if (!hook_byte) {
		OutputDebugString(TEXT("VirtualAlloc Error"));
		return  FALSE;
	}
	//원래 api 주소 +5 로 점프하기 위한 계산
	DWORD jmp_addr = (DWORD)pFunc + 5 - ((DWORD)hook_byte + (BYTE)5) - 5;
	memcpy(&calc_byte[6], &jmp_addr, 4);

	VirtualProtect((LPVOID)hook_byte, 10, PAGE_EXECUTE_READWRITE, &dwOldProtect);
	memcpy(hook_byte, calc_byte, 10);
	VirtualProtect((LPVOID)hook_byte, 10, dwOldProtect, &dwOldProtect);

	OrgNTAPI[idx] = hook_byte;

	VirtualProtect((LPVOID)pFunc, 5, PAGE_EXECUTE_READWRITE, &dwOldProtect);
	dwAddress = (DWORD)pfnNew - (DWORD)pFunc - 5;
	memcpy(&pBuf[1], &dwAddress, 4);
	memcpy(pFunc, pBuf, 5);
	VirtualProtect((LPVOID)pFunc, 5, dwOldProtect, &dwOldProtect);

	return TRUE;
}
VOID Hook() {
	BOOL ret;
	wchar_t msg[100];
	Init();
	for (int i = 0; i < WINAPI_NUM; i++) {
		HMODULE hMod = GetModuleHandle(ConvertMultibyteToUnicode(winapi->dll_list[i]));
		ret = hook_iat(winapi->dll_list[i], GetProcAddress(hMod, winapi->api_list[i]), (PROC)winapi->function_list[i], i);
		if (!ret) {
			lstrcpy(msg, ConvertMultibyteToUnicode(winapi->api_list[i]));
			lstrcat(msg, TEXT(" HOOK FAIL(WINAPI)"));
			OutputDebugString(msg);
		}
	}
	for (int i = 0; i < NTAPI_NUM; i++) {
		//if (i == 9 || i == 12)continue;
		ret = hook_code("ntdll.dll", ntapi->NTapi_list[i], (PROC)ntapi->NTfunction_list[i], i);
		if (!ret) {
			lstrcpy(msg, ConvertMultibyteToUnicode(ntapi->NTapi_list[i]));
			lstrcat(msg, TEXT(" HOOK FAIL(NTAPI)"));
			OutputDebugString(msg);
		}
	}
}