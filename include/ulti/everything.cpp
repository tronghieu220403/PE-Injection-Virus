#include "everything.h"


DWORD Align(DWORD value, DWORD alignment)
{
    if (value % alignment == 0)
    {
        return value;
    }
    else
    {
        return (value/alignment + 1)*alignment;
    }
}

void ZeroMem(void* data, int size)
{
    for (int i = 0; i < size; i++)
    {
        *((unsigned char*)(data)+i) = 0;
    }
}

void MemCopy(void* dst, void *src, int size)
{
    for (int i = 0; i < size; i++)
    {
        *((unsigned char*)(dst)+i) = *((unsigned char*)(src)+i);
    }
}

BYTE StrCmp(void* str1, void *str2)
{
    for (int i = 0; ; i++)
    {
        if (*((unsigned char*)(str1)+i) != *((unsigned char*)(str2)+i))
        {
            return 0;
        }
        if (*((unsigned char*)(str1)+i) == 0 || *((unsigned char*)(str2)+i) == 0)
        {
            return 1;
        }
    }
}

unsigned long long MemoryToUint64(unsigned char* data)
{
    unsigned long long ans = 0;
    memcpy(&ans, data, 8);
    return ans;
}
