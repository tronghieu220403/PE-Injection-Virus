#include "pecpp.h"

namespace pe
{
    PortableExecution::PortableExecution(const std::string_view &full_path):
        name_(full_path)
    {
        std::filesystem::path p{full_path};
        data_.resize(std::filesystem::file_size(p));
        std::ifstream ifs(p, std::ios_base::binary);
        if (ifs.good())
        {
            ifs.read((char *)&data_[0], data_.size());
        }
        ifs.close();
    }

    DWORD PortableExecution::GetEntryPoint() const
    {
        return ::GetEntryPoint((PVOID)&data_[0]);
    }

    void PortableExecution::SetEntryPoint(DWORD entry_point)
    {
        return ::SetEntryPoint((PVOID)&data_[0], entry_point);
    }

    std::vector<unsigned char> PortableExecution::GetData() const
    {
        return data_;
    }

    void PortableExecution::SetData(const std::vector<unsigned char> data)
    {
        data_ = data;
    }

    bool PortableExecution::IsValidExe()
    {
        return IsValidExeFile((PVOID)&data_[0]);
    }

    bool PortableExecution::Is64Bit()
    {
        return Is64BitExecutable((PVOID)&data_[0]);
    }

    std::vector<unsigned char> PortableExecution::GetCodeSectionOfEntryPoint()
    {
        std::vector<unsigned char> code_section_data;
        PIMAGE_SECTION_HEADER code_section_header = ::GetCodeSectionOfEntryPoint((PVOID)&data_[0]);

        DWORD begin_offset = code_section_header->PointerToRawData;
        DWORD end_offfset =  begin_offset + code_section_header->SizeOfRawData;

        if (code_section_header != NULL)
        {
            std::copy (&data_[begin_offset], &data_[end_offfset], std::back_inserter(code_section_data));
        }
        return code_section_data;
    }

    std::vector<unsigned char> PortableExecution::GetSectionData(const std::string_view &section_name)
    {
        std::vector<unsigned char> section_data;
        PIMAGE_SECTION_HEADER section_header = GetSectionHeader(section_name);
        if (section_header != NULL)
        {
            DWORD begin_offset = section_header->PointerToRawData;
            DWORD end_offfset =  begin_offset + section_header->SizeOfRawData;

            std::copy (&data_[begin_offset], &data_[end_offfset], std::back_inserter(section_data));
        }
        return section_data;
    }

    PIMAGE_SECTION_HEADER PortableExecution::GetSectionHeader(const std::string_view &section_name)
    {
        if (section_name.size() > 8)
        {
            return NULL;
        }
        unsigned long long section_name_ull = 0;
        memcpy(&section_name_ull, &section_name[0], section_name.size());

        PIMAGE_DOS_HEADER p_image_dos_header;
        PIMAGE_SECTION_HEADER p_image_section_header;
        ULONG number_of_sections;
        DWORD entry_address = 0;

        p_image_dos_header = (PIMAGE_DOS_HEADER)&data_[0];
        if (this->Is64Bit())
        {
            PIMAGE_NT_HEADERS64 p_image_nt_headers_64;
            p_image_nt_headers_64 = (PIMAGE_NT_HEADERS64)((PUCHAR)&data_[0] + p_image_dos_header->e_lfanew);
            p_image_section_header = (PIMAGE_SECTION_HEADER)(p_image_nt_headers_64 + 1);
            number_of_sections = p_image_nt_headers_64->FileHeader.NumberOfSections;
            entry_address = p_image_nt_headers_64->OptionalHeader.AddressOfEntryPoint;
        }
        else
        {
            PIMAGE_NT_HEADERS32 p_image_nt_headers_32;
            p_image_nt_headers_32 = (PIMAGE_NT_HEADERS32)((PUCHAR)&data_[0] + p_image_dos_header->e_lfanew);
            p_image_section_header = (PIMAGE_SECTION_HEADER)(p_image_nt_headers_32 + 1);
            number_of_sections = p_image_nt_headers_32->FileHeader.NumberOfSections;
            entry_address = p_image_nt_headers_32->OptionalHeader.AddressOfEntryPoint;

        }

        for (unsigned int i = 0; i < number_of_sections; i++)
        {
            if (::MemoryToUint64(p_image_section_header[i].Name) == section_name_ull)
            {
                return &p_image_section_header[i];
            }
        }
        return NULL;
    }

    void PortableExecution::FlushChange()
    {
        std::ofstream ofs(name_, std::ios_base::binary);
        ofs.write((char *)&data_[0], data_.size());
        ofs.close();
    }
}
