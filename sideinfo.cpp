
#include <Windows.h>
#include <iostream>
#include <vector>
using namespace std;

int main()
{
    vector<string> a;
    a.push_back("LoadLibraryExA");
    a.push_back("GetProcAddress");
    a.push_back("FindFirstFileA");
    a.push_back("FindNextFileA");
    a.push_back("FindClose");
    a.push_back("CreateFileA");
    a.push_back("GetFileSize");
    a.push_back("ReadFile");
    a.push_back("CloseHandle");
    a.push_back("VirtualAlloc");
    a.push_back("VirtualFree");
    a.push_back("CreateFileMappingA");
    a.push_back("MapViewOfFile");
    a.push_back("FlushViewOfFile");
    a.push_back("UnmapViewOfFile");
    a.push_back("NtClose");
    a.push_back("CheckSumMappedFile");
    a.push_back("GetEnvironmentVariableA");
    a.push_back("CloseHandle");
    a.push_back("WriteFile");
    a.push_back("CreateThread");
    a.push_back("CreateMutexA");
    a.push_back("WaitForSingleObject");

    for (string& s: a)
    {
        DWORD hash = 0;
        for (int i = 0; i < s.size() ; i++)
        {
            hash = (hash * 26 + s[i]) % (DWORD)(1e9+7);
        }
        hash = (hash * 26 + 0) % (DWORD)(1e9+7);
        cout << "p" << s << "   " << "fn" << s << ";      // 0x" << hex << hash << endl;
    }
    string s = ".hieu";
    cout << "char virus_name[" << s.size() + 1 << "];\n"; 
    for (int i = 0; i < s.size(); i++)
    {
        cout << "virus_name[" << i << "] = \'" << s[i] << "\'; " << endl;
    }
    cout << "virus_name[" << s.size() << "] = 0" << endl;
    cout << endl;

}