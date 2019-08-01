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