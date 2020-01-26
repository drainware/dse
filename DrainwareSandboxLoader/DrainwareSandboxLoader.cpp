// DrainwareSandboxLoader.cpp: define las funciones exportadas de la aplicación DLL.
//

#include "stdafx.h"

HMODULE g_hATP = NULL;

DWORD WINAPI ThreadLoadSandBoxDelay( LPVOID lpvArgument )
{

	while( true )
	{
	Sleep( 100 ); //Give some time to load other dll;
	//LoadSandBox();
		#if defined(_DW64_)
					HMODULE hDll = LoadLibrary( _T("DrainwareSandbox64.dll") );
		#else
					HMODULE hDll = LoadLibrary( _T("DrainwareSandbox32.dll") );
		#endif
					if( hDll )
						break;
	}

	return 0;
}


void LoadSandBox()
{
	TCHAR szModuleName[ MAX_PATH ];
	LPTSTR pszEXE;

	GetModuleFileName( NULL, szModuleName, MAX_PATH );
	pszEXE = _tcsrchr(szModuleName, '\\');
	if( pszEXE )
	{
		++pszEXE;
		CString strApp;
		CString strName = pszEXE;
		strName.MakeUpper();
		CRegKey kSandBoxApps;
		LONG lRes = kSandBoxApps.Open( HKEY_LOCAL_MACHINE, _T("SOFTWARE\\Drainware\\SecurityEndpoint\\Sandbox\\Applications"), KEY_READ );
		if( lRes != ERROR_SUCCESS )
			lRes = kSandBoxApps.Open( HKEY_LOCAL_MACHINE, _T("SOFTWARE\\Drainware\\SecurityEndpoint\\Sandbox\\Applications"), KEY_READ | KEY_WOW64_64KEY );
		if (lRes == ERROR_SUCCESS)
		{
			DWORD nIndex = 0;
			DWORD dwSize = MAX_PATH;
			while( kSandBoxApps.EnumKey( nIndex++, szModuleName, &dwSize ) == ERROR_SUCCESS )
			{
				strApp = szModuleName;
				strApp.MakeUpper();
				if( strApp == strName )
				{
		#if defined(_DW64_)
					g_hATP = LoadLibrary( _T("DrainwareSandbox64.dll") );
		#else
					g_hATP = LoadLibrary( _T("DrainwareSandbox32.dll") );
		#endif
					//CloseHandle( CreateThread(NULL, 0, ThreadLoadSandBoxDelay, NULL, 0, NULL) );
					break;
				}
				dwSize = MAX_PATH;
			}
		}
		else
		{
			DWORD dw = GetLastError();
			dw = 0;
		}
	}
}
