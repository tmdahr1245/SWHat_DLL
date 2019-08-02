#include "Util.hpp"
HANDLE hEvent, hThread;
DWORD dwThreadID;
void WaitThreadStart() {
	hEvent = OpenEvent(EVENT_ALL_ACCESS, TRUE, TEXT("finish"));
	hThread = (HANDLE)_beginthreadex(NULL, 0, WaitForExit, NULL, 0, (unsigned*)& dwThreadID);
}
unsigned int WINAPI WaitForExit(LPVOID lpParam){
	WaitForSingleObject(hEvent, INFINITE);

	ExitProcess(1);
}

wchar_t* ConvertMultibyteToUnicode(char* str) {
	wchar_t* pStr;
	int strSize = MultiByteToWideChar(CP_ACP, 0, str, -1, NULL, NULL);

	pStr = (wchar_t*)malloc(sizeof(wchar_t) * strSize);
	MultiByteToWideChar(CP_ACP, 0, str, strlen(str) + 1, pStr, strSize);
	return pStr;
}
char* ConvertUnicodeToMultibyte(wchar_t* str){
	char* pStr;
	int strSize = WideCharToMultiByte(CP_ACP, 0, str, -1, NULL, 0, NULL, NULL);

	pStr = new char[strSize];
	WideCharToMultiByte(CP_ACP, 0, str, -1, pStr, strSize, 0, 0);
	return pStr;
}
char* GetProcessName(DWORD pid) {
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	char ret[100];
	if (hSnapshot) {
		PROCESSENTRY32 ProcessEntry32;
		BOOL bProcessFound;
		ProcessEntry32.dwSize = sizeof(PROCESSENTRY32);
		bProcessFound = Process32First(hSnapshot, &ProcessEntry32);
		while (bProcessFound) {
			if (ProcessEntry32.th32ProcessID == pid) {
				strcpy(ret, ConvertUnicodeToMultibyte(ProcessEntry32.szExeFile));
				break;
			}
			bProcessFound = Process32Next(hSnapshot, &ProcessEntry32);
		}
	}
	CloseHandle(hSnapshot);
	return ret;
}