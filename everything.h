#define BUFSIZE 512

#define WINVER 0x0A00
#define _WIN32_WINNT _WIN32_WINNT_WIN10

#include <Windows.h>
#include <winternl.h>
#include <imagehlp.h>

#include <iostream>

using namespace std;

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
    _Out_writes_bytes_to_opt_(nNumberOfBytesToRead, *lpNumberOfBytesRead) __out_data_source(FILE) LPVOID lpBuffer,
    _In_ DWORD nNumberOfBytesToRead,
    _Out_opt_ LPDWORD lpNumberOfBytesRead,
    _Inout_opt_ LPOVERLAPPED lpOverlapped
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


typedef struct _IAT
{
    // kernel32.dll
    pLoadLibraryExA     fnLoadLibraryExA;
    pGetProcAddress     fnGetProcAddress;

    pFindFirstFileA     fnFindFirstFileA;
    pFindNextFileA      fnFindNextFileA;
    pFindClose          fnFindClose;

    pCreateFileA        fnCreateFileA;
    pGetFileSize        fnGetFileSize;
    pReadFile           fnReadFile;
    pCloseHandle        fnCloseHandle;

    pVirtualAlloc       fnVirtualAlloc;
    pVirtualFree        fnVirtualFree;

    pCreateFileMappingA fnCreateFileMappingA;
    pMapViewOfFile      fnMapViewOfFile;
    pFlushViewOfFile    fnFlushViewOfFile;
    pUnmapViewOfFile    fnUnmapViewOfFile;

    // ntdll.dll
    pNtClose            fnNtClose;

    // Imagehlp.dll
    pCheckSumMappedFile fnCheckSumMappedFile;
} IAT, *PIAT;