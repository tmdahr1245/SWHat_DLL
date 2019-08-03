#include <windows.h>

#include <iostream>
#include <vector>
using namespace std;
extern wchar_t log_name[11];
extern HANDLE hLogFile;
void Log(vector<pair<string, string>> v, wchar_t* buf = NULL, ULONG Length = 0, const char* name = NULL);
void LogFileOpen();
void LogFileClose();