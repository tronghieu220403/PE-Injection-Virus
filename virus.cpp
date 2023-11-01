

#include "shared.h"

#include <iostream>
using namespace std;

void InfectFile(char*, _DATA*)
{
    return;
}

void WINAPI EmptyFunction(PDATA data)
{
    //PDATA data = *(PDATA *)param;
    cout << "OKE" << endl;
    cout << hex << (unsigned long long)data << endl;
    cout << hex << (unsigned long long)data->iat->fnCreateThread << endl;
    return;
}

int main()
{
    //PIAT iat = (PIAT)malloc(sizeof(IAT));
    //PDATA data = (PDATA)malloc(sizeof(DATA));
    IAT iat;
    DATA data;
    data.iat = &iat;

    GetFunctionAddresses(&data);

    //LPVOID param = (LPVOID)malloc(1000);
    //*(PDATA *)param = data;

    cout << hex << (unsigned long long)(&data) << endl;
    cout << hex << (unsigned long long)(data.iat->fnCreateThread) << endl;

    EmptyFunction(&data);

    data.iat->fnWaitForSingleObject(data.iat->fnCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)&EmptyFunction, (PVOID)(&data), 0, NULL), INFINITE);

}