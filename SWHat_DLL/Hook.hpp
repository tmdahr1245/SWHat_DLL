#include <windows.h>

VOID HookInit();
VOID HookStart();

BOOL hook_code(LPCSTR szDllName, LPCSTR szFuncName, PROC pfnNew, DWORD idx);
BOOL hook_iat(LPCSTR szDllName, PROC pfnOrg, PROC pfnNew, DWORD idx);
