#include "Hook.hpp"
#include "Log.hpp"
#include "Util.hpp"
//유니코드
//mt
//미리컴파일된 헤더 사용안함
//증분링크 사용안함
#pragma warning(disable: 4996)
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved){
	switch (fdwReason)	{
	case DLL_PROCESS_ATTACH:
		LogFileOpen();
		WaitThreadStart();
		HookStart();
		break;
	case DLL_PROCESS_DETACH:
		//닫기 전이나 후에 바로 서버로 로그전송
		LogFileClose();
		OutputDebugString(TEXT("finish"));
		break;
	}
	return TRUE;
}