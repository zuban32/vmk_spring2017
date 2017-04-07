#include "pe_parser.h"
#include <locale.h>

int main( int argc, char** argv )
{
  UINT codePage = GetConsoleOutputCP( );
  SetConsoleOutputCP( CYRILLIC_CODE_PAGE ); // set code page to display russian symbols
  setlocale( LC_ALL, "Russian" );

  HANDLE fileHandle = GetFileFromArguments( argc, argv );
  if( NULL != fileHandle )
  {
    DWORD fileSize = CheckFileSizeForCorrectness( GetFileSize( fileHandle, NULL ) );
    if( INVALID_FILE_SIZE != fileSize )
    {
      char* buffer = ( char* ) malloc( fileSize );
      int readSize = ReadFileToBuffer( fileHandle, buffer, fileSize );
      if( readSize != fileSize )
      {
        printf( CAN_NOT_READ_ENTIRE_FILE );
      }
      else
      {
        ChangeEntryPoint( buffer, fileSize, argv[ 0x01 ] );
      }
      free( buffer );
    }
    CloseHandle( fileHandle );
  }
  SetConsoleOutputCP( codePage );  // restore code page
  return 0x00;
}
