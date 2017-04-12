#include "pe_parser.h"
#include "pe.h"
#include <string.h>
#include <time.h>

static int patchCavern(PEFile *pe, char *buffer, DWORD bufSize)
{
	printf("Patch mode - cavern\n");
	for (int i = 0; i < pe->file_hdr->NumberOfSections; i++) {
		IMAGE_SECTION_HEADER *sect = pe->sect_hdr_start + i;
		if (sect->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
			DWORD code_min_start = sect->VirtualAddress + sect->Misc.VirtualSize;
			DWORD code_max_start = sect->VirtualAddress + sect->SizeOfRawData - GetMaxCodeSize();
			if (code_max_start < code_min_start) {
				printf("Cavern isn't big enough\n");
			} else {
				DWORD code_off = 0;
				if (code_max_start > code_min_start) {
					code_off = rand() % (code_max_start - code_min_start);
				}
				printf("Random code offset = %#x\n", code_off);
				DWORD code_start = code_min_start + code_off;
				ENTRY_POINT_CODE code = GetEntryPointCodeSmall(code_start,
					pe->opt_hdr->AddressOfEntryPoint);
				memcpy(buffer + sect->PointerToRawData + sect->Misc.VirtualSize + code_off,
					code.code,
					code.sizeOfCode);
				pe->opt_hdr->AddressOfEntryPoint = code_start;
				return 1;
			}
		}
	}
	return 0;
}

static int patchExtSect(PEFile *pe, char *buffer, DWORD bufSize)
{
	printf("Patch mode - section extension\n");
	for (int i = 0; i < pe->file_hdr->NumberOfSections; i++) {
		IMAGE_SECTION_HEADER *sect = pe->sect_hdr_start + i;
		if (sect->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
			DWORD aligned_next_addr = ((sect->VirtualAddress + sect->SizeOfRawData) &
				(-pe->opt_hdr->SectionAlignment)) + pe->opt_hdr->SectionAlignment;
			DWORD code_max_start = min(sect->VirtualAddress + sect->SizeOfRawData +
				pe->opt_hdr->FileAlignment - GetMaxCodeSize(), aligned_next_addr - GetMaxCodeSize());
			DWORD code_min_start = sect->VirtualAddress + sect->SizeOfRawData;
			if (code_max_start < code_min_start) {
				printf("Can't extend the section\n");
			} else {
				DWORD code_off = 0;
				if (code_max_start > code_min_start) {
					code_off = rand() % (code_max_start - code_min_start);
				}
				printf("Random code offset = %#x\n", code_off);
				DWORD code_start = code_min_start + code_off;
				DWORD data_shift = (code_off / pe->opt_hdr->FileAlignment + 1) * pe->opt_hdr->FileAlignment;
				ENTRY_POINT_CODE code = GetEntryPointCodeSmall(code_start,
					pe->opt_hdr->AddressOfEntryPoint);

				memmove(buffer + sect->PointerToRawData + sect->SizeOfRawData + data_shift,
					buffer + sect->PointerToRawData + sect->SizeOfRawData,
					bufSize - sect->PointerToRawData - sect->SizeOfRawData);

				memcpy(buffer + sect->PointerToRawData + sect->SizeOfRawData + code_off,
					code.code,
					code.sizeOfCode);
				pe->opt_hdr->AddressOfEntryPoint = code_start;
				sect->Misc.VirtualSize = sect->SizeOfRawData + code_off + code.sizeOfCode;
				sect->SizeOfRawData += data_shift;
				pe->opt_hdr->SizeOfCode += data_shift;

				for (int j = 0; j < pe->file_hdr->NumberOfSections; j++) {
					if (pe->sect_hdr_start[j].PointerToRawData > sect->PointerToRawData) {
						pe->sect_hdr_start[j].PointerToRawData += data_shift;
					}
				}
				return 1;
			}
		}
	}
	return 0;
}

static int patchNewSect(PEFile *pe, char *buffer, DWORD bufSize)
{
	printf("Patch mode - new section\n");

	DWORD chars;
	DWORD min_addr = (DWORD)-1, max_addr = 0;
	DWORD last_size = 0;
	for (int i = 0; i < pe->file_hdr->NumberOfSections; i++) {
		IMAGE_SECTION_HEADER *sect = pe->sect_hdr_start + i;
		if (sect->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
			chars = sect->Characteristics;
		}
		if (sect->VirtualAddress < min_addr) {
			min_addr = sect->VirtualAddress;
		} else if (sect->VirtualAddress > max_addr) {
			max_addr = sect->VirtualAddress;
			last_size = sect->SizeOfRawData;
		}
	}

	if (min_addr - ((char *)(pe->sect_hdr_start + pe->file_hdr->NumberOfSections) + sizeof(IMAGE_SECTION_HEADER) - buffer)
		< sizeof(IMAGE_SECTION_HEADER)) {
		printf("New section patching impossible\n");
	} else {
		DWORD code_off = rand() % (pe->opt_hdr->SectionAlignment - GetMaxCodeSize());
		printf("Random code offset = %#x\n", code_off);

		IMAGE_SECTION_HEADER new_section;
		new_section.Characteristics = chars;
		new_section.VirtualAddress = ((max_addr + last_size) & (-pe->opt_hdr->SectionAlignment))
			+ pe->opt_hdr->SectionAlignment;
		memcpy(new_section.Name, ".text1\0", 7);
		new_section.SizeOfRawData = (code_off / pe->opt_hdr->FileAlignment + 1) * pe->opt_hdr->FileAlignment;
		new_section.Misc.VirtualSize = code_off + GetMaxCodeSize();
		new_section.PointerToRawData = bufSize;
		memcpy(pe->sect_hdr_start + pe->file_hdr->NumberOfSections, &new_section, sizeof(new_section));

		pe->file_hdr->NumberOfSections++;
		pe->opt_hdr->SizeOfImage += pe->opt_hdr->SectionAlignment;
		pe->opt_hdr->SizeOfHeaders += sizeof(new_section);

		ENTRY_POINT_CODE code = GetEntryPointCodeSmall(new_section.VirtualAddress + code_off, pe->opt_hdr->AddressOfEntryPoint);
		memcpy(buffer + bufSize + code_off, code.code, code.sizeOfCode);
		pe->opt_hdr->AddressOfEntryPoint = new_section.VirtualAddress + code_off;
		return 1;
	}
	return 0;
}

void ChangeEntryPoint(char* buffer, DWORD bufferSize, char* originalFilename, bool *reallocated)
{
	*reallocated = false;
	srand(time(NULL));
	PatchMode m = static_cast<PatchMode>(rand() % PATCH_TOTAL);

	PEFile pe;
	if (ParsePE(buffer, bufferSize, &pe)) {
		printf("File error - incorrect PE\n");
		return;
	}

	DWORD newBufferSize = bufferSize;
	if (m != PATCH_CAVERN) {
		if (m == PATCH_EXTSECT) {
			newBufferSize += pe.opt_hdr->FileAlignment;
		} else {
			newBufferSize += pe.opt_hdr->SectionAlignment;
		}
		buffer = (char *)realloc(buffer, newBufferSize);
		if (!buffer) {
			printf("Error reallocing - return\n");
			return;
		}
		*reallocated = true;
		if (ParsePE(buffer, newBufferSize, &pe)) {
			printf("File error - incorrect PE after reallocation\n");
			return;
		}
	}

	bool patch_done = false;

	if (m == PATCH_CAVERN) {
		patch_done = patchCavern(&pe, buffer, bufferSize);
	} else if (m == PATCH_EXTSECT) {
		patch_done = patchExtSect(&pe, buffer, bufferSize);
	} else if (m == PATCH_NEWSECT) {
		patch_done = patchNewSect(&pe, buffer, bufferSize);
	}

	int len = strlen(originalFilename);
	char *new_name = (char *)calloc(len + 2, sizeof(*new_name));
	memcpy(new_name + 1, originalFilename, len);
	new_name[0] = '1';
	new_name[len + 1] = 0;
	WriteFileFromBuffer(new_name, buffer, newBufferSize);
	free(new_name);

	if (patch_done) {
		printf("File succesfully patched\n");
	}
}

static char byteCode[] = {
	0xE8, 0x00, 0x00, 0x00,
	0x00, 0x50, 0x8B, 0x44,
	0x24, 0x04, 0x05, 0x77,
	0x77, 0x77, 0x77, 0x89,
	0x44, 0x24, 0x04, 0x58,
	0xC3 };

DWORD GetMaxCodeSize()
{
	return sizeof(byteCode);
}

ENTRY_POINT_CODE GetEntryPointCodeSmall(DWORD rvaToNewEntryPoint, DWORD rvaToOriginalEntryPoint)
{
	ENTRY_POINT_CODE code;
	DWORD offsetToOriginalEntryPoint = rvaToOriginalEntryPoint - rvaToNewEntryPoint - SIZE_OF_CALL_INSTRUCTION;
	DWORD* positionOfOffsetToOriginalEntryPoint = GetPositionOfPattern(byteCode, sizeof(byteCode), OFFSET_PATTERN);
	if (NULL != positionOfOffsetToOriginalEntryPoint)
	{
		*positionOfOffsetToOriginalEntryPoint = offsetToOriginalEntryPoint;
		code.sizeOfCode = sizeof(byteCode);
		code.code = (char*)malloc(code.sizeOfCode);
		memcpy(code.code, byteCode, code.sizeOfCode);
	} else
	{
		code.code = NULL;
		code.sizeOfCode = 0x00;
	}
	return code;
}

DWORD* GetPositionOfPattern(char* buffer, DWORD bufferSize, DWORD pattern)
{
	DWORD* foundPosition = NULL;
	char* position;
	char* lastPosition = buffer + bufferSize - sizeof(DWORD);

	for (position = buffer; position <= lastPosition; ++position)
	{
		if (*((DWORD*)position) == pattern)
		{
			foundPosition = (DWORD*)position;
			break;
		}
	}
	return foundPosition;
}