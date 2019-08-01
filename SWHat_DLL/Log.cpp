#include "rapidjson/document.h"
#include "rapidjson/prettywriter.h"
#include "rapidjson/writer.h"
#include "rapidjson/filewritestream.h"
#include <cstdio>
#include <cstdlib>
#include <atlstr.h>
#include <Windows.h>
#pragma warning(disable: 4996)
using namespace rapidjson;
FILE* fp;
HANDLE hMutex;

void LogFileOpen() {
	hMutex = CreateMutex(NULL, FALSE, NULL);
	fp = fopen("test.json", "a+");//추가한다면 a로 하고 계쏙 새로 쓴다면 w로 해야함
}
void LogFileClose() {
	fclose(fp);
}
void Log2(wchar_t* log) {

	WaitForSingleObject(hMutex, INFINITE);
	SYSTEMTIME cur_time;
	GetLocalTime(&cur_time);

	CString strTime;
	strTime.Format(L"[%02d:%02d:%02d.%03d]", cur_time.wHour, cur_time.wMinute, cur_time.wSecond, cur_time.wMilliseconds, cur_time);

	wchar_t buf[1000];
	_stprintf(buf, L"%s%s\n", strTime, log);
	fwprintf(fp, buf);
	//fwprintf(fp, L"%s\n", log);
	ReleaseMutex(hMutex);
}
void Log() {

	StringBuffer s;
	Writer<StringBuffer> writer(s);

	writer.StartObject();
	writer.Key("hello");
	writer.String("world");
	writer.Key("t");
	writer.Bool(true);
	writer.Key("f");
	writer.Bool(false);
	writer.Key("n");
	writer.Null();
	writer.Key("i");
	writer.Uint(123);
	writer.Key("pi");
	writer.Double(3.1416);
	writer.Key("a");
	writer.StartArray();
	for (unsigned i = 0; i < 4; i++)
		writer.Uint(i);
	writer.EndArray();
	writer.EndObject();
	
	//FILE* fp = fopen("test.json", "a+");//추가한다면 a로 하고 계쏙 새로 쓴다면 w로 해야함
	//fprintf(fp, "U1dIYXQ=%s\n", s.GetString());
	fprintf(fp, "%s\n", s.GetString());
	//fclose(fp); 
}