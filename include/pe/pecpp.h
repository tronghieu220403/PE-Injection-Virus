#include "pe.h"

#include <string>
#include <vector>
#include <filesystem>
#include <fstream>

namespace pe
{
    struct SECTION
    {
        IMAGE_SECTION_HEADER header;
        std::vector<unsigned char> data;
    };

    class PortableExecutable
    {
        private:
            std::vector<unsigned char> data_;
            std::string name_;

        public:

            PortableExecutable() = default;
            PortableExecutable(const std::string_view& full_path);

            DWORD GetEntryPoint() const;
            void SetEntryPoint(DWORD entry_point);

            std::vector<unsigned char> GetData() const;
            void SetData(const std::vector<unsigned char> data);

            bool IsValidExe();
            bool Is64Bit();

            SECTION GetCodeSectionOfEntryPoint();

            SECTION GetSectionData(const std::string_view& section_name);
            PIMAGE_SECTION_HEADER GetSectionHeader(const std::string_view& section_name);

            void FlushChange();
    };
}