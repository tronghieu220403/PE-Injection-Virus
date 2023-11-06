#include "pe.h"

#include <string>
#include <vector>
#include <filesystem>
#include <fstream>

namespace pe
{
    class PortableExecution
    {
        private:
            std::vector<unsigned char> data_;
            std::string name_;

        public:

            PortableExecution() = default;
            PortableExecution(const std::string_view& full_path);

            DWORD GetEntryPoint() const;
            void SetEntryPoint(DWORD entry_point);

            std::vector<unsigned char> GetData() const;
            void SetData(const std::vector<unsigned char> data);

            bool IsValidExe();
            bool Is64Bit();

            std::vector<unsigned char> GetCodeSectionOfEntryPoint();

            std::vector<unsigned char> GetSectionData(const std::string_view& section_name);
            PIMAGE_SECTION_HEADER GetSectionHeader(const std::string_view& section_name);

            void FlushChange();
    };
}