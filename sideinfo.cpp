
#include <Windows.h>
#include <iostream>

using namespace std;

int main()
{

    wstring s = L"kernel32.dll";
    DWORD hash = 0;
    for (int i = 0; i < s.size() ; i++)
    {
        hash = (hash * 26 + s[i]) % (DWORD)(1e9+7);
    }
    hash = (hash * 26 + 0) % (DWORD)(1e9+7);
    cout << hash;

}