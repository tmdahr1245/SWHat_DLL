#include "rapidjson/document.h"
#include "rapidjson/prettywriter.h"
#include "rapidjson/writer.h"
#include "rapidjson/filewritestream.h"
#include "Log.hpp"
#include "Util.hpp"
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <vector>
#include <tchar.h>
#include <Windows.h>

#pragma warning(disable: 4996)

using namespace rapidjson;
using namespace std;

FILE* fp;
HANDLE hMutex, hLogFile;
wchar_t log_name[11];
BOOL startLogging = FALSE;

void LogFileOpen() {
	StringBuffer s;
	Writer<StringBuffer> writer(s);
	hMutex = CreateMutex(NULL, FALSE, NULL);
	DWORD pid = GetCurrentProcessId();
	wchar_t buf[10];
	lstrcpy(log_name, L"C:\\");
	lstrcat(log_name, _ultow(pid, buf, 10));
	lstrcat(log_name, L".json");
	hLogFile = CreateFile(log_name, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	writer.StartObject();
	writer.Key("pid");
	writer.Uint((unsigned int)pid);
	writer.Key("process");
	writer.String(GetProcessName(pid));
	writer.EndObject();
	DWORD dwByte;
	WriteFile(hLogFile, s.GetString(), strlen(s.GetString()), &dwByte, NULL);
	WriteFile(hLogFile, "\n", strlen("\n"), &dwByte, NULL);
	startLogging = TRUE;

}
void LogFileClose() {
	CloseHandle(hLogFile);
}
void Log(vector<pair<string,string>> v, wchar_t* buf, ULONG Length, const char* name) {
	if (startLogging) {
		WaitForSingleObject(hMutex, INFINITE);
		SYSTEMTIME cur_time;
		GetLocalTime(&cur_time);
		char time[100];
		sprintf(time, "[%02d:%02d:%02d.%03d]", cur_time.wHour, cur_time.wMinute, cur_time.wSecond, cur_time.wMilliseconds);
		StringBuffer s;
		Writer<StringBuffer> writer(s);
		writer.StartObject();
		writer.Key("time");
		writer.String(time);
		for (auto& i : v) {
			writer.Key(i.first.c_str());
			writer.String(i.second.c_str());
		}
		if (name) {
			writer.Key(name);
			writer.RawNumber((char*)buf, Length);
		}

		writer.EndObject();

		DWORD dwByte;
		WriteFile(hLogFile, s.GetString(), strlen(s.GetString()), &dwByte, NULL);
		WriteFile(hLogFile, "\n", strlen("\n"), &dwByte, NULL);
		ReleaseMutex(hMutex);
	}
}