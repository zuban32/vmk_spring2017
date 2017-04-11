#include "pe_parser.h"
#include <string.h>
#include <time.h>

bool CheckPE(char *fileBuf, DWORD bufSize)
{
	IMAGE_DOS_HEADER *dos_header = (IMAGE_DOS_HEADER *)fileBuf;
	if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
		printf("This is not a PE file\n");
		return false;
	}

	IMAGE_NT_HEADERS32 *nt_headers = (IMAGE_NT_HEADERS32 *)(fileBuf + dos_header->e_lfanew);

	if (nt_headers->Signature != IMAGE_NT_SIGNATURE) {
		printf("Doesn't have NT headers: signature = %x\n", nt_headers->Signature);
		return false;
	}

	if (nt_headers->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
		printf("Incorrect optional header magic! (%x)\n", nt_headers->OptionalHeader.Magic);
		return false;
	}
	return true;
}

void ChangeEntryPoint( char* buffer, DWORD bufferSize, char* originalFilename, bool *reallocated )
{
  // TODO: Необходимо изменить точку входа в программу (AddressOfEntryPoint).
  // Поддерживаются только 32-разрядные файлы (или можете написать свой код точки входа для 64-разрядных)
  // Варианты размещения новой точки входа - в каверне имеющихся секций, в расширеннной области 
  // секций или в новой секции. Подробнее:
  //    Каверна секции - это разница между SizeOfRawData и VirtualSize. Так как секция хранится
  //      на диске с выравниванием FileAlignment (обычно по размеру сектора, 0x200 байт), а в VirtualSize 
  //      указан точный размер секции в памяти, то получается, что на диске хранится лишних
  //      ( SizeOfRawData - VirtualSize ) байт. Их можно использовать.
  //    Расширенная область секции - так как в памяти секции выравниваются по значению SectionAlignment 
  //      (обычно по размеру страницы, 0x1000), то следующая секция начинается с нового SectionAlignment.
  //      Например, если SectionAlignment равен 0x1000, а секция занимает всего 0x680 байт, то в памяти будет
  //      находится еще 0x980 нулевых байт. То есть секцию можно расширить (как в памяти, так и на диске)
  //      и записать в нее данные.
  //    Новая секция - вы можете создать новую секцию (если места для еще одного заголовка секции достаточно)
  //      Легче всего добавить последнюю секцию. Необходимо помнить о всех сопутствующих добавлению новой секции 
  //      изменениях: заголовок секции, атрибуты секции, поле NumberOfSections в IMAGE_FILE_HEADER и т.д.
  // После выбора места для размещения необходимо получить код для записи в файл. Для этого можно 
  // воспользоваться функцией GetEntryPointCodeSmall. Она возвращает структуру ENTRY_POINT_CODE, ее описание
  // находится в заголовочном файле. Необходимо проверить, что код был успешно сгенерирован. После чего
  // записать новую точку входа в выбранное место. После этого вызвать функцию WriteFileFromBuffer. Имя файла 
  // можно сформировать по имени исходного файла (originalFilename). 
  // 

	*reallocated = false;
	srand(time(NULL));
	PatchMode m = static_cast<PatchMode>(rand() % PATCH_TOTAL);

	IMAGE_DOS_HEADER *dos_header = (IMAGE_DOS_HEADER *)buffer;

	IMAGE_NT_HEADERS32 *nt_headers = (IMAGE_NT_HEADERS32 *)(buffer + dos_header->e_lfanew);
	IMAGE_FILE_HEADER *file_header = &(nt_headers->FileHeader);
	IMAGE_OPTIONAL_HEADER32 *opt_header = &(nt_headers->OptionalHeader);

	DWORD newBufferSize = bufferSize;
	if (m != PATCH_CAVERN) {
		if (m == PATCH_EXTSECT) {
			newBufferSize += opt_header->FileAlignment;
		} else {
			newBufferSize += opt_header->SectionAlignment;
		}
		buffer = (char *)realloc(buffer, newBufferSize);
		if (!buffer) {
			printf("Error reallocing - return\n");
			return;
		}
		*reallocated = true;
	}

	dos_header = (IMAGE_DOS_HEADER *)buffer;
	nt_headers = (IMAGE_NT_HEADERS32 *)(buffer + dos_header->e_lfanew);
	file_header = &(nt_headers->FileHeader);
	opt_header = &(nt_headers->OptionalHeader);

	DWORD sections_offset = sizeof(*nt_headers);
	ULONGLONG entry_point, ep_offset;

	entry_point = opt_header->AddressOfEntryPoint;
	ep_offset = dos_header->e_lfanew + offsetof(IMAGE_NT_HEADERS32, OptionalHeader) +
		offsetof(IMAGE_OPTIONAL_HEADER32, AddressOfEntryPoint);

	bool ep_done = false;

	DWORD chars;
	IMAGE_SECTION_HEADER *sect_hdr = (IMAGE_SECTION_HEADER *)(buffer + dos_header->e_lfanew + sections_offset);

	if (m == PATCH_CAVERN) {
		printf("Patch mode - cavern\n");
		for (int i = 0; i < file_header->NumberOfSections; i++) {
			if (sect_hdr[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
				DWORD code_min_start = sect_hdr[i].VirtualAddress + sect_hdr[i].Misc.VirtualSize;
				DWORD code_max_start = sect_hdr[i].VirtualAddress + sect_hdr[i].SizeOfRawData - GetMaxCodeSize();
				if (code_max_start < code_min_start) {
					printf("Cavern isn't big enough\n");
				} else {
					DWORD code_off = 0;
					if (code_max_start > code_min_start) {
						code_off = rand() % (code_max_start - code_min_start);
					}
					printf("Random code offset = %x\n", code_off);
					DWORD code_start = code_min_start + code_off;
					ENTRY_POINT_CODE code = GetEntryPointCodeSmall(code_start,
						opt_header->AddressOfEntryPoint);
					memcpy(buffer + sect_hdr[i].PointerToRawData + sect_hdr[i].Misc.VirtualSize + code_off, 
						code.code, 
						code.sizeOfCode);
					opt_header->AddressOfEntryPoint = code_start;
					ep_done = true;
					break;
				}
			}
		}
	} else if (m == PATCH_EXTSECT) {
		printf("Patch mode - section extension\n");
		for (int i = 0; i < file_header->NumberOfSections; i++) {
			if (sect_hdr[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
				printf("Section[%d]: %s\n addr = %x, size = %x\n",
					i,
					sect_hdr[i].Name,
					sect_hdr[i].VirtualAddress + opt_header->ImageBase,
					sect_hdr[i].SizeOfRawData);
				DWORD aligned_next_addr = ((sect_hdr[i].VirtualAddress + sect_hdr[i].SizeOfRawData) & 
					(-opt_header->SectionAlignment)) + opt_header->SectionAlignment;
				printf("Aligned next addr = %x\n", aligned_next_addr);
				DWORD code_max_start = min(sect_hdr[i].VirtualAddress + sect_hdr[i].SizeOfRawData + 
					opt_header->FileAlignment - GetMaxCodeSize(), aligned_next_addr - GetMaxCodeSize());
				DWORD code_min_start = sect_hdr[i].VirtualAddress + sect_hdr[i].SizeOfRawData;
				if (code_max_start < code_min_start) {
					printf("Can't extend the section\n");
					printf("Next = %x, cur = (%x - %x)\n", 
						aligned_next_addr, 
						sect_hdr[i].VirtualAddress, 
						sect_hdr[i].SizeOfRawData);
				} else {
					DWORD code_off = 0;
					if (code_max_start > code_min_start) {
						code_off = rand() % (code_max_start - code_min_start);
					}
					printf("Random code offset = %x\n", code_off);
					DWORD code_start = code_min_start + code_off;
					DWORD data_shift = (code_off / opt_header->FileAlignment + 1) * opt_header->FileAlignment;
					ENTRY_POINT_CODE code = GetEntryPointCodeSmall(code_start,
						opt_header->AddressOfEntryPoint);

					memmove(buffer + sect_hdr[i].PointerToRawData + sect_hdr[i].SizeOfRawData + data_shift,
						buffer + sect_hdr[i].PointerToRawData + sect_hdr[i].SizeOfRawData,
						bufferSize - sect_hdr[i].PointerToRawData - sect_hdr[i].SizeOfRawData);

					memcpy(buffer + sect_hdr[i].PointerToRawData + sect_hdr[i].SizeOfRawData + code_off, 
						code.code, 
						code.sizeOfCode);
					opt_header->AddressOfEntryPoint = code_start;
					sect_hdr[i].Misc.VirtualSize = sect_hdr[i].SizeOfRawData + code_off + code.sizeOfCode;
					sect_hdr[i].SizeOfRawData += data_shift;
					opt_header->SizeOfCode += data_shift;

					for (int j = 0; j < file_header->NumberOfSections; j++) {
						if (sect_hdr[j].PointerToRawData > sect_hdr[i].PointerToRawData) {
							sect_hdr[j].PointerToRawData += data_shift;
						}
					}

					ep_done = true;
					break;
				}
			}
		}
	} else if (m == PATCH_NEWSECT) {
		printf("Patch mode - new section\n");
		DWORD min_addr = (DWORD)-1, max_addr = 0;
		DWORD last_size = 0;
		for (int i = 0; i < file_header->NumberOfSections; i++) {
			if (sect_hdr[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
				chars = sect_hdr[i].Characteristics;
			}
			if (sect_hdr[i].VirtualAddress < min_addr) {
				min_addr = sect_hdr[i].VirtualAddress;
			} else if (sect_hdr[i].VirtualAddress > max_addr) {
				max_addr = sect_hdr[i].VirtualAddress;
				last_size = sect_hdr[i].SizeOfRawData;
			}
		}

		if (min_addr - ((char *)(sect_hdr + file_header->NumberOfSections) + sizeof(IMAGE_SECTION_HEADER) - buffer)
			< sizeof(IMAGE_SECTION_HEADER)) {
			printf("New section patching impossible\n");
		} else {
			DWORD code_off = rand() % (opt_header->SectionAlignment - GetMaxCodeSize());
			printf("Random code offset = %x\n", code_off);

			IMAGE_SECTION_HEADER new_section;
			new_section.Characteristics = chars;
			new_section.VirtualAddress = ((max_addr + last_size) & (-opt_header->SectionAlignment))
				+ opt_header->SectionAlignment;
			memcpy(new_section.Name, ".text1\0", 7);
			new_section.SizeOfRawData = (code_off / opt_header->FileAlignment + 1) * opt_header->FileAlignment;
			new_section.Misc.VirtualSize = code_off + GetMaxCodeSize();
			new_section.PointerToRawData = bufferSize;
			memcpy(sect_hdr + file_header->NumberOfSections, &new_section, sizeof(new_section));

			file_header->NumberOfSections++;
			opt_header->SizeOfImage += opt_header->SectionAlignment;
			opt_header->SizeOfHeaders += sizeof(new_section);

			ENTRY_POINT_CODE code = GetEntryPointCodeSmall(new_section.VirtualAddress + code_off, opt_header->AddressOfEntryPoint);
			memcpy(buffer + bufferSize + code_off, code.code, code.sizeOfCode);
			opt_header->AddressOfEntryPoint = new_section.VirtualAddress + code_off;
			ep_done = true;
		}
	}

	int len = strlen(originalFilename);
	char *new_name = (char *)calloc(len + 2, sizeof(*new_name));
	memcpy(new_name+1, originalFilename, len);
	new_name[0] = '1';
	new_name[len + 1] = 0;
	WriteFileFromBuffer(new_name, buffer, newBufferSize);
	free(new_name);

	if (ep_done) {
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

ENTRY_POINT_CODE GetEntryPointCodeSmall( DWORD rvaToNewEntryPoint, DWORD rvaToOriginalEntryPoint )
{
  ENTRY_POINT_CODE code;
  DWORD offsetToOriginalEntryPoint = rvaToOriginalEntryPoint - rvaToNewEntryPoint - SIZE_OF_CALL_INSTRUCTION;
  DWORD* positionOfOffsetToOriginalEntryPoint = GetPositionOfPattern( byteCode, sizeof( byteCode ), OFFSET_PATTERN );
  if( NULL != positionOfOffsetToOriginalEntryPoint )
  {
    *positionOfOffsetToOriginalEntryPoint = offsetToOriginalEntryPoint;
    code.sizeOfCode = sizeof( byteCode );
    code.code = ( char* ) malloc( code.sizeOfCode );
    memcpy( code.code, byteCode, code.sizeOfCode );
  }
  else
  {
    code.code = NULL;
    code.sizeOfCode = 0x00;
  }
  return code;
}

DWORD* GetPositionOfPattern( char* buffer, DWORD bufferSize, DWORD pattern )
{
  DWORD* foundPosition = NULL;
  char* position;
  char* lastPosition = buffer + bufferSize - sizeof( DWORD );

  for( position = buffer; position <= lastPosition; ++position )
  {
    if( *( ( DWORD* ) position ) == pattern )
    {
      foundPosition = ( DWORD* ) position;
      break;
    }
  }
  return foundPosition;
}