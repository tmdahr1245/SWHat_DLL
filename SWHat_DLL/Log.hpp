#include <windows.h>
#include <iostream>
#include <vector>
#include <list>

using namespace std;

extern wchar_t log_name[11];
extern HANDLE hLogFile;
extern list<HANDLE> hList;

void Log(vector<pair<string, string>> v, wchar_t* buf = NULL, ULONG Length = 0, const char* name = NULL);
void LogFileOpen();
void LogFileClose();

void InsertHandle(HANDLE handle);
BOOL SearchRemoveHandle(HANDLE handle);

template<typename T>
void push_back_format(vector<pair<string, string>>& v, const char* buf, T value, const char* name) {
	char tt[1000];
	sprintf(tt, buf, value);
	v.push_back({ name, tt });
}