#include <windows.h>
#include <winternl.h>
#define NTAPI_NUM 5


typedef void* PPS_CREATE_INFO, * PPS_ATTRIBUTE_LIST;

extern LPVOID OrgNTAPI[NTAPI_NUM];

extern LPVOID MyNtFunc[NTAPI_NUM];

//File
NTSTATUS NTAPI MyNtCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize OPTIONAL, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer OPTIONAL, ULONG EaLength);
NTSTATUS NTAPI MyNtWriteFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key);

//Process
NTSTATUS NTAPI MyNtCreateUserProcess(PHANDLE ProcessHandle,PHANDLE ThreadHandle,ACCESS_MASK ProcessDesiredAccess,ACCESS_MASK ThreadDesiredAccess,POBJECT_ATTRIBUTES ProcessObjectAttributes,POBJECT_ATTRIBUTES ThreadObjectAttributes,ULONG ProcessFlags,ULONG ThreadFlags,PRTL_USER_PROCESS_PARAMETERS ProcessParameters,PPS_CREATE_INFO CreateInfo,PPS_ATTRIBUTE_LIST AttributeList);
NTSTATUS NTAPI MyNtWriteVirtualMemory(HANDLE ProcessHandle, LPVOID BaseAddress, LPCVOID Buffer, ULONG NumberOfBytesToWrite, ULONG* NumberOfBytesWritten); 

//MISC
NTSTATUS NTAPI MyNtClose(HANDLE Handle);