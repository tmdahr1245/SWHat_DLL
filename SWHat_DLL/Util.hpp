#include <process.h>
#include <windows.h>
#include <tlhelp32.h>

#pragma warning(disable: 4996)

extern HANDLE hThread;
extern HANDLE hEvent;
extern DWORD dwThreadID;

void WaitThreadStart();
unsigned int WINAPI WaitForExit(LPVOID lpParam);
wchar_t* ConvertMultibyteToUnicode(char* str);
char* ConvertUnicodeToMultibyte(wchar_t* str);
char* GetProcessName(DWORD pid);