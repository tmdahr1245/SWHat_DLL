#include <windows.h>

VOID Init();
VOID Hook();

BOOL hook_code(LPCSTR szDllName, LPCSTR szFuncName, PROC pfnNew, DWORD idx);
BOOL hook_iat(LPCSTR szDllName, PROC pfnOrg, PROC pfnNew, DWORD idx);