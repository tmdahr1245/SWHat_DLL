#include "Hook.hpp"
#include "Log.hpp"
#include "Util.hpp"
//유니코드
//mt
//미리컴파일된 헤더 사용안함
//증분링크 사용안함
#pragma warning(disable: 4996)
//HANDLE hThread;
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved){
	switch (fdwReason)	{
	case DLL_PROCESS_ATTACH:
		WaitThreadStart();
		Hook();
		LogFileOpen();//후킹 이후에 호출해야함
		break;
	case DLL_PROCESS_DETACH:
		//여기서 test.json닫아주고
		//서버로 전송
		LogFileClose();
		OutputDebugString(TEXT("finish"));
		//test
		break;
	}
	return TRUE;
}