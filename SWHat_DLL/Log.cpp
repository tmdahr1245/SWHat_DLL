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
wchar_t log_name[100];
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
void Log22(wchar_t* log) {
	WaitForSingleObject(hMutex, INFINITE);
	SYSTEMTIME cur_time;
	GetLocalTime(&cur_time);
	wchar_t time[100];
	_stprintf(time, L"[%02d:%02d:%02d.%03d]", cur_time.wHour, cur_time.wMinute, cur_time.wSecond, cur_time.wMilliseconds);

	wchar_t buf[1000];
	_stprintf(buf, L"%s%s\n", time, log);
	//fwprintf(fp, buf);
	DWORD dwByte;
	//WriteFile(hLogFile, buf, lstrlen(buf)*sizeof(wchar_t), &dwByte, NULL);
	ReleaseMutex(hMutex);
}
void Log(vector<pair<string,pair<string,string>>> v) {
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
			char type[10];
			writer.Key(i.second.first.c_str());
			strcpy(type, i.first.c_str());
			if (!strcmp(type,"int")) {
				//writer.Int(atoi(i.second.second.c_str()));
				
				writer.String(i.second.second.c_str());
			}
			else if (!strcmp(type, "string")) {
				writer.String(i.second.second.c_str());
			}
		}
		writer.EndObject();
		//FILE* fp = fopen("test.json", "a+");//추가한다면 a로 하고 계쏙 새로 쓴다면 w로 해야함
		//fprintf(fp, "U1dIYXQ=%s\n", s.GetString());
		//fprintf(fp, "%s\n", s.GetString());
		DWORD dwByte;
		WriteFile(hLogFile, s.GetString(), strlen(s.GetString()), &dwByte, NULL);
		WriteFile(hLogFile, "\n", strlen("\n"), &dwByte, NULL);
		//fclose(fp); 
		ReleaseMutex(hMutex);
	}
}
void LogWithBuffer(vector<pair<string, pair<string, string>>> v, wchar_t* buf, ULONG Length, const char* name) {
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
			char type[10];
			writer.Key(i.second.first.c_str());
			strcpy(type, i.first.c_str());
			if (!strcmp(type, "int")) {
				//writer.Int(atoi(i.second.second.c_str()));

				writer.String(i.second.second.c_str());
			}
			else if (!strcmp(type, "string")) {
				writer.String(i.second.second.c_str());
			}
		}
		writer.Key(name);
		//writer.String((char*)buf);
		//writer.RawValue((char*)buf,Length, kStringType);
		writer.RawNumber((char*)buf,Length);
		writer.EndObject();

		//FILE* fp = fopen("test.json", "a+");//추가한다면 a로 하고 계쏙 새로 쓴다면 w로 해야함
		//fprintf(fp, "U1dIYXQ=%s\n", s.GetString());
		//fprintf(fp, "%s\n", s.GetString());
		DWORD dwByte;
		WriteFile(hLogFile, s.GetString(), strlen(s.GetString()), &dwByte, NULL);
		WriteFile(hLogFile, "\n", strlen("\n"), &dwByte, NULL);
		//fclose(fp); 
		ReleaseMutex(hMutex);
	}
}
void test() {
	//map<자료형,pair<이름,값>> m;
}