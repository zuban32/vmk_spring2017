#include <Windows.h>
#include <stdio.h>

#define BUFFER_SIZE 0x1000
#define CYRILLIC_CODE_PAGE 1251 

HANDLE GetFileFromArguments(int argc, char **argv);
unsigned int ReadFileToBuffer(HANDLE fileHandle, char buffer[BUFFER_SIZE]);
void PrintHelp(char* programName);
void PrintError(char* functionFrom);
void ProcessFile(HANDLE f, char* buffer, int bufferSize);


int main(int argc, char **argv)
{
	UINT codePage = GetConsoleOutputCP();
	SetConsoleOutputCP(CYRILLIC_CODE_PAGE); // set code page to display russian symbols

	HANDLE fileHandle = GetFileFromArguments(argc, argv);
	if (fileHandle) {
		char buffer[BUFFER_SIZE];
		int readSize = ReadFileToBuffer(fileHandle, buffer);
		if (readSize != 0) {
			ProcessFile(fileHandle, buffer, readSize);
		}
	}

	CloseHandle(fileHandle);
	SetConsoleOutputCP(codePage);  // restore code page
	return 0;
}

HANDLE GetFileFromArguments(int argc, char **argv)
{
	HANDLE fileHandle = NULL;
	if (argc == 2) {
		fileHandle = CreateFileA(argv[1], GENERIC_READ, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (INVALID_HANDLE_VALUE == fileHandle) {
			PrintError("CreateFileA");
		}
	} else {
		PrintHelp(argv[0]);
	}
	return fileHandle;
}

unsigned int ReadFileToBuffer(HANDLE fileHandle, char buffer[BUFFER_SIZE])
{
	unsigned int returnValue = 0x00;
	if (NULL != fileHandle) {
		unsigned int fileSize = GetFileSize(fileHandle, NULL);
		if (INVALID_FILE_SIZE == fileSize) {
			PrintError("GetFileSize");
		} else {
			unsigned long bytesRead;
			fileSize = min(fileSize, BUFFER_SIZE);
			if (true == ReadFile(fileHandle, buffer, fileSize, &bytesRead, NULL)) {
				returnValue = bytesRead;
			} else {
				PrintError("ReadFile");
			}
		}
	}
	return returnValue;
}

void ProcessFile(HANDLE f, char* buffer, int bufferSize)
{
	IMAGE_DOS_HEADER *dos_header = (IMAGE_DOS_HEADER *)buffer;
	if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
		printf("This is not a PE file\n");
		return;
	}

	DWORD pe_sign = *((DWORD *)(buffer + dos_header->e_lfanew));
	IMAGE_FILE_HEADER *file_header = (IMAGE_FILE_HEADER *)(buffer + dos_header->e_lfanew + sizeof(pe_sign));

	if (pe_sign != IMAGE_NT_SIGNATURE) {
		printf("Doesn't have NT headers: signature = %#x\n", pe_sign);
		return;
	}

	bool is32 = false;
	WORD opt_magic = *(WORD *)((char *)file_header + sizeof(*file_header));

	if (opt_magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
		is32 = true;
	} else if (opt_magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		printf("Incorrect optional header magic! (%#x)\n", opt_magic);
		return;
	}

	DWORD sections_offset = is32 ? sizeof(IMAGE_NT_HEADERS32) : sizeof(IMAGE_NT_HEADERS64);
	ULONGLONG entry_point, ep_offset, ib;
	if (is32) {
		IMAGE_NT_HEADERS32 *nth = (IMAGE_NT_HEADERS32 *)(buffer + dos_header->e_lfanew);
		entry_point = nth->OptionalHeader.AddressOfEntryPoint;
		ib = nth->OptionalHeader.ImageBase;
		ep_offset = dos_header->e_lfanew + offsetof(IMAGE_NT_HEADERS32, OptionalHeader) +
			offsetof(IMAGE_OPTIONAL_HEADER32, AddressOfEntryPoint);
	} else {
		IMAGE_NT_HEADERS64 *nth = (IMAGE_NT_HEADERS64 *)(buffer + dos_header->e_lfanew);
		entry_point = nth->OptionalHeader.AddressOfEntryPoint;
		ib = nth->OptionalHeader.ImageBase;
		ep_offset = dos_header->e_lfanew + offsetof(IMAGE_NT_HEADERS32, OptionalHeader) +
			offsetof(IMAGE_OPTIONAL_HEADER64, AddressOfEntryPoint);
	}

	bool found = false;

	printf("Entry point (%#llx)\n", entry_point);

	IMAGE_SECTION_HEADER *sect_hdr = (IMAGE_SECTION_HEADER *)(buffer + dos_header->e_lfanew + sections_offset);
	for (int i = 0; i < file_header->NumberOfSections; i++) {
		if (sect_hdr[i].VirtualAddress <= entry_point
			&& entry_point < sect_hdr[i].VirtualAddress + sect_hdr[i].SizeOfRawData) {
			printf("In section %d, %s\n", i, sect_hdr[i].Name);
			printf("Offset in section %#llx %.02f%%\n",
				entry_point - sect_hdr[i].VirtualAddress,
				100 * ((float)(entry_point - sect_hdr[i].VirtualAddress) / sect_hdr[i].Misc.VirtualSize));
			found = true;
			break;
		}
	}
	if (!found) {
		printf("Error: no entry point section found (???)\n");
	}
}

#pragma region __ Print functions __
void PrintHelp(char* programName)
{
	printf("Usage:\n%s <filename>\n", programName);
}

void PrintError(char* functionFrom)
{
	char* errorMessage;
	DWORD errorCode = GetLastError();

	// Retrieve the system error message for the last-error code
	FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		errorCode,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPTSTR)&errorMessage,
		0, NULL);

	printf("In function %s, error %d:\n%s\n", functionFrom, errorCode, errorMessage);
	LocalFree(errorMessage);
}

#pragma endregion

