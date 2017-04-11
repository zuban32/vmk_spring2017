#include "pe_parser.h"
#include <locale.h>
#include <stdio.h>
#include <conio.h>


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
			int readSize = ReadFileToBuffer(fileHandle, buffer, fileSize);
			if (readSize != fileSize)
			{
				printf(CAN_NOT_READ_ENTIRE_FILE);
			} else if (!CheckPE(buffer, fileSize))
			{
				printf(NOT_PE_FILE);
			}
			else
			{
				if (!buffer) {
					printf("Error reallocing - exit\n");
				} else {
					ChangeEntryPoint(buffer, fileSize, argv[1]);
				}
			}
			free(buffer);
		}
		CloseHandle(fileHandle);
	}
	SetConsoleOutputCP(codePage);  // restore code page
	_getch();
	return 0;
}
