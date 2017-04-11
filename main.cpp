#include "pe_parser.h"
#include <locale.h>
#include <stdio.h>


int main(int argc, char** argv)
{
	UINT codePage = GetConsoleOutputCP();
	SetConsoleOutputCP(CYRILLIC_CODE_PAGE); // set code page to display russian symbols
	setlocale(LC_ALL, "Russian");

	HANDLE fileHandle = GetFileFromArguments(argc, argv);
	if (NULL != fileHandle)
	{
		DWORD fileSize = CheckFileSizeForCorrectness(GetFileSize(fileHandle, NULL));
		if (INVALID_FILE_SIZE != fileSize)
		{
			char* buffer = (char*)malloc(fileSize);
			if (!buffer) {
				printf("Error mallocing\n");
				return 1;
			}
			int readSize = ReadFileToBuffer(fileHandle, buffer, fileSize);
			bool reallocated = false;
			if (readSize != fileSize)
			{
				printf(CAN_NOT_READ_ENTIRE_FILE);
			} else if (!CheckPE(buffer, fileSize))
			{
				printf(NOT_PE_FILE);
			}
			else
			{
				ChangeEntryPoint(buffer, fileSize, argv[1], &reallocated);
			}
			if(!reallocated) {
				free(buffer);
			}
		}
		CloseHandle(fileHandle);
	}
	SetConsoleOutputCP(codePage);  // restore code page
	return 0;
}
