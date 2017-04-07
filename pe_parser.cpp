#include "pe_parser.h"

void ParseFile( char* buffer, DWORD bufferSize )
{
  // TODO: Необходимо выполнить разбор файла и написать в какой секции располагается точка входа. 
  // Вывод должен быть в следующем формате 
  // ## Entry point (<значение точки входа>)
  // ## In section <индекс секции>, <название секции>
  // ## Offset in section <смещение относительно начала секции>, <смещение в процентах> %
  // 
  // Где смещение в процентах вычисляется относительно размера секции. Например, если секция имеет 
  // размер 1000, а точка входа располагается по смещению 400 в ней, то необходимо вывести 40 %.
  //
  // Все используемые структуры можно посмотреть в заголовочном файле WinNT.h (он уже подключен, так
  // как указан в Windows.h). Например вам могут потребоваться следующие структуры:
  //IMAGE_DOS_HEADER заголовок, который используется в системе DOS (сейчас вам в нем потребуется только поле e_lfanew (что оно означает?)
  //IMAGE_NT_HEADERS заголовок нового формата исполняемого файла (PE), используемого в Windows NT
  //IMAGE_FILE_HEADER один из двух заголовков, из которых состоит IMAGE_NT_HEADER, содержит NumberOfSections
  //IMAGE_OPTIONAL_HEADER второй заголовок IMAGE_NT_HEADER, содержит важные для нас поля ImageBase и AddressOfEntryPoint
  //IMAGE_SECTION_HEADER заголовок секции, в нем содержится название, размер и расположение секции
  //
  // Не забывайте проверять такие поля как сигнатуры файлов (ведь надо убедиться, что разбираем собственно исполняемый файл)
  printf( "Buffer length: %d\nImplement parsing of file\n", bufferSize );
}

void ChangeEntryPoint( char* buffer, DWORD bufferSize, char* originalFilename )
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

}

ENTRY_POINT_CODE GetEntryPointCodeSmall( DWORD rvaToNewEntryPoint, DWORD rvaToOriginalEntryPoint )
{
  ENTRY_POINT_CODE code;
  char byteCode[] = { 0xE8, 0x00, 0x00, 0x00, 0x00, 0x50, 0x8B, 0x44, 0x24, 0x04, 0x05, 0x77, 0x77, 0x77, 0x77, 0x89, 0x44, 0x24, 0x04, 0x58, 0xC3 };
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