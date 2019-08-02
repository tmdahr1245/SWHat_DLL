#include <windows.h>

#include <iostream>
#include <vector>
using namespace std;
extern wchar_t log_name[100];
extern HANDLE hLogFile;
void Log(vector<pair<string, pair<string, string>>> v);
void LogWithBuffer(vector<pair<string, pair<string, string>>> v, wchar_t* buf, ULONG Length, const char* name);
void LogFileOpen();
void LogFileClose();