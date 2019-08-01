#include <process.h>
#include <windows.h>
extern HANDLE hThread;
extern HANDLE hEvent;
extern DWORD dwThreadID;
void WaitThreadStart();
unsigned int WINAPI WaitForExit(LPVOID lpParam);