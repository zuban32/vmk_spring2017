#include "pe_parser.h"  


HANDLE GetFileFromArguments( int argc, char** argv )
{
  HANDLE fileHandle = NULL;
  if( 0x02 == argc )
  {
    fileHandle = CreateFileA( argv[ 0x01 ], GENERIC_READ, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL );
    if( INVALID_HANDLE_VALUE == fileHandle )
    {
      PrintError( "CreateFileA" );
    }
  }
  else
  {
    PrintHelp( argv[ 0x00 ] );
  }
  return fileHandle;
}

DWORD ReadFileToBuffer( HANDLE fileHandle, char* buffer, DWORD bufferSize )
{
  DWORD returnValue = 0x00;
  if( NULL != fileHandle )
  {
    DWORD bytesRead;
    if( true == ReadFile( fileHandle, buffer, bufferSize, &bytesRead, NULL ) )
    {
      returnValue = bytesRead;
    }
    else
    {
      PrintError( "ReadFile" );
    }
  }
  return returnValue;
}

DWORD WriteFileFromBuffer( char* filename, char* buffer, DWORD bufferSize )
{
  DWORD returnValue = 0x00;

  HANDLE fileHandle = CreateFileA( filename, GENERIC_WRITE, NULL, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL );
  if( INVALID_HANDLE_VALUE == fileHandle )
  {
    PrintError( "CreateFileA" );
  }

  if( NULL != fileHandle )
  {
    DWORD bytesWritten;
    if( true == WriteFile( fileHandle, buffer, bufferSize, &bytesWritten, NULL ) )
    {
      returnValue = bytesWritten;
    }
    else
    {
      PrintError( "WriteFile" );
    }
    CloseHandle( fileHandle );
  }
  return returnValue;
}

DWORD CheckFileSizeForCorrectness( DWORD fileSize )
{
  if( INVALID_FILE_SIZE == fileSize )
  {
    PrintError( "GetFileSize" );
  }
  else if( MAX_FILE_SIZE_ALLOWED_TO_READ < fileSize )
  {
    printf( TOO_LARGE_FILE );
    fileSize = INVALID_FILE_SIZE;
  }
  else if( 0x00 == fileSize )
  {
    printf( NULL_FILE_SIZE );
    fileSize = INVALID_FILE_SIZE;
  }
  return fileSize;
}