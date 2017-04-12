#pragma once
#include <Windows.h>
#include <stdio.h>

#pragma region __ Constants __
#define BUFFER_SIZE 0x1000
#define CYRILLIC_CODE_PAGE 1251 
#define MEGABYTE 1048576
#define MAX_FILE_SIZE_ALLOWED_TO_READ 20 * MEGABYTE
#define SIZE_OF_CALL_INSTRUCTION 5
#define OFFSET_PATTERN 0x77777777

#define CAN_NOT_READ_ENTIRE_FILE "Can not read entire file"
#define TOO_LARGE_FILE "File is larger than allowed, can not parse"
#define NULL_FILE_SIZE "File has size of 0"  
#define NOT_PE_FILE "This file is not PE"

enum PatchMode {
	PATCH_CAVERN,
	PATCH_EXTSECT,
	PATCH_NEWSECT,
	PATCH_TOTAL
};

#pragma endregion


#pragma region __ Structures __
struct ENTRY_POINT_CODE
{
  DWORD sizeOfCode;
  char* code;
};
#pragma endregion


#pragma region __ Functions __
HANDLE GetFileFromArguments( int argc, char** argv );
DWORD ReadFileToBuffer( HANDLE fileHandle, char* buffer, DWORD bufferSize );
DWORD WriteFileFromBuffer( char* filename, char* buffer, DWORD bufferSize );
void ChangeEntryPoint( char* buffer, DWORD bufferSize, char* originalFilename, bool *reallocated );
DWORD CheckFileSizeForCorrectness( DWORD fileSize );
DWORD* GetPositionOfPattern( char* buffer, DWORD bufferSize, DWORD pattern );
DWORD GetMaxCodeSize();
ENTRY_POINT_CODE GetEntryPointCodeSmall( DWORD rvaToNewEntryPoint, DWORD rvaToOriginalEntryPoint );

void PrintError( char* functionFrom );
void PrintHelp( char* programName );
#pragma endregion

