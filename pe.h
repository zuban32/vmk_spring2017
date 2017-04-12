#pragma once
#include <Windows.h>

typedef struct {
	IMAGE_DOS_HEADER *dos_hdr;
	IMAGE_NT_HEADERS32 *nt_hdr;
	IMAGE_FILE_HEADER *file_hdr;
	IMAGE_OPTIONAL_HEADER32 *opt_hdr;
	IMAGE_SECTION_HEADER *sect_hdr_start;
} PEFile;

int ParsePE(char *fileBuf, DWORD bufSize, PEFile *res);
