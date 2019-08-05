#include "rapidjson/prettywriter.h"
#include "rapidjson/writer.h"
#include "Log.hpp"
#include "Util.hpp"
#include <cstdio>
#include <cstdlib>
#include <tchar.h>

#pragma warning(disable: 4996)

using namespace rapidjson;

FILE* fp;
HANDLE hMutex, hLogFile;
wchar_t log_name[11];
BOOL startLogging = FALSE;
list<HANDLE> hList;

StringBuffer sMain;
PrettyWriter<StringBuffer> MainWriter(sMain);

void InsertHandle(HANDLE handle) {
	hList.push_back(handle);
}
BOOL SearchRemoveHandle(HANDLE handle) {
	auto it = find(hList.begin(), hList.end(), handle);

	if (it != hList.end()) {
		hList.remove(handle);
		return TRUE;
	}
	else
		return FALSE;
}
void CloseRemainingHandle() {
	for (auto i : hList) {
		vector<pair<string, string>> v;
		v.push_back({ "api", "MyNtClose" });
		push_back_format(v, "0x%x", i, "Handle");
		push_back_format(v, "0x%x", 0, "ret");

		Log(v);
	}
}
void LogFileOpen() {
	hMutex = CreateMutex(NULL, FALSE, NULL);

	DWORD pid = GetCurrentProcessId();
	wchar_t buf[10];
	DWORD dwByte;

	lstrcpy(log_name, L"C:\\");
	lstrcat(log_name, _ultow(pid, buf, 10));
	lstrcat(log_name, L".json");

	hLogFile = CreateFile(log_name, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	
	MainWriter.StartObject();

	MainWriter.Key("pid");
	MainWriter.Uint((unsigned int)pid);

	MainWriter.Key("process");
	MainWriter.String(GetProcessName(pid));

	MainWriter.Key("log");
	MainWriter.StartArray();

	startLogging = TRUE; 
}
void LogFileClose() {
	DWORD dwByte;
	CloseRemainingHandle();

	MainWriter.EndArray();
	MainWriter.EndObject();

	WriteFile(hLogFile, sMain.GetString(), sMain.GetLength(), &dwByte, NULL);

	CloseHandle(hLogFile);
}
void Log(vector<pair<string,string>> v, wchar_t* buf, ULONG Length, const char* name) {
	if (startLogging) {
		WaitForSingleObject(hMutex, INFINITE);

		SYSTEMTIME cur_time;
		DWORD dwByte;

		GetLocalTime(&cur_time);
		char time[100];
		sprintf(time, "[%02d:%02d:%02d.%03d]", cur_time.wHour, cur_time.wMinute, cur_time.wSecond, cur_time.wMilliseconds);

		StringBuffer sLog;
		Writer<StringBuffer> LogWriter(sLog);

		LogWriter.StartObject();
		LogWriter.Key("time");
		LogWriter.String(time);

		for (auto& i : v) {
			LogWriter.Key(i.first.c_str());
			LogWriter.String(i.second.c_str());
		}
		if (name) {
			LogWriter.Key(name);
			LogWriter.RawNumber((char*)buf, Length);
		}

		LogWriter.EndObject();
		MainWriter.RawValue(sLog.GetString(), sLog.GetLength(), kObjectType);
		WriteFile(hLogFile, sMain.GetString(), sMain.GetLength(), &dwByte, NULL);
		sMain.Clear();
		ReleaseMutex(hMutex);
	}
}