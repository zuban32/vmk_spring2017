#include "pe.h"
#include <stdio.h>

int ParsePE(char *fileBuf, DWORD bufSize, PEFile *res)
{
	if (bufSize < sizeof(IMAGE_DOS_HEADER)) {
		return 1;
	}

	IMAGE_DOS_HEADER *dos_header = (IMAGE_DOS_HEADER *)fileBuf;
	if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
		printf("This is not a PE file\n");
		return 1;
	}

	if (dos_header->e_lfanew < 0 || dos_header->e_lfanew > bufSize || dos_header->e_lfanew + sizeof(IMAGE_NT_HEADERS32) > bufSize) {
		return 1;
	}

	IMAGE_NT_HEADERS32 *nt_headers = (IMAGE_NT_HEADERS32 *)(fileBuf + dos_header->e_lfanew);

	if (nt_headers->Signature != IMAGE_NT_SIGNATURE) {
		printf("Doesn't have NT headers: signature = %x\n", nt_headers->Signature);
		return 1;
	}

	if (nt_headers->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
		printf("Incorrect optional header magic! (%x)\n", nt_headers->OptionalHeader.Magic);
		return 1;
	}

	if (dos_header->e_lfanew + sizeof(*nt_headers) + nt_headers->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER) >= bufSize) {
		return 1;
	}
	IMAGE_SECTION_HEADER *sect_hdr = (IMAGE_SECTION_HEADER *)(fileBuf + dos_header->e_lfanew + sizeof(*nt_headers));

	res->dos_hdr = dos_header;
	res->nt_hdr = nt_headers;
	res->file_hdr = &nt_headers->FileHeader;
	res->opt_hdr = &nt_headers->OptionalHeader;
	res->sect_hdr_start = sect_hdr;

	return 0;
}
