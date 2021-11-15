#include "debug.hxx"
#include <windows.h>
#include <stdio.h>
#include <strsafe.h>

#ifndef NDEBUG
void _DBGPRINT( const char* kwszFunction, int iLineNumber, const wchar_t* kwszDebugFormatString, ... ) \
{
    INT cbFormatString = 0;
    va_list args;
    PWCHAR wszDebugString = NULL;
    size_t st_Offset = 0;

    va_start( args, kwszDebugFormatString );

    cbFormatString = _scwprintf( L"[%S:%d] ", kwszFunction, iLineNumber ) * sizeof( WCHAR );
    cbFormatString += _vscwprintf( kwszDebugFormatString, args ) * sizeof( WCHAR ) + 2;

    wszDebugString = (PWCHAR)malloc( cbFormatString );

    if(wszDebugString == nullptr){
        //not a lot we can do here
        OutputDebugStringW(L"Failed to allocate memory for output string");
    }else{
        /* Populate the buffer with the contents of the format string. */
        StringCbPrintfW( wszDebugString, cbFormatString, L"[%S:%d] ", kwszFunction, iLineNumber );
        StringCbLengthW( wszDebugString, cbFormatString, &st_Offset );
        StringCbVPrintfW( &wszDebugString[st_Offset / sizeof(WCHAR)], cbFormatString - st_Offset, kwszDebugFormatString, args );

        OutputDebugStringW( wszDebugString );

        free( wszDebugString );
    }

    va_end( args );
}
#endif
