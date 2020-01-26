// dllmain.cpp : Define el punto de entrada de la aplicación DLL.
#include "stdafx.h"

extern HMODULE g_hATP;
void LoadSandBox();

DWORD WINAPI ThreadLoadSandBox( LPVOID lpvArgument )
{
	Sleep( 2000 );
	LoadSandBox();
	return 0;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	HANDLE hThread = NULL;
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		{
			//hThread = CreateThread(NULL, 0, ThreadLoadSandBox, NULL, 0, NULL);
			//CloseHandle( CreateThread(NULL, 0, ThreadLoadSandBox, NULL, 0, NULL) );
			//TCHAR szModuleName[ MAX_PATH ];
			//LPTSTR pszEXE;

			//GetModuleFileName( NULL, szModuleName, MAX_PATH );
			//pszEXE = _tcsrchr(szModuleName, '\\');
			//CString strName = pszEXE;
			//strName.MakeUpper();
			//if( !lstrcmp( _T("ACRORD32.EXE"), strName ) )
			//	MessageBox( NULL, _T("Acrord32.exe"), _T("Info"), MB_ICONWARNING );
			LoadSandBox();
		}
	break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	break;
	case DLL_PROCESS_DETACH:
		//if( hThread )
		//	WaitForSingleObject( hThread, 2000 );
		//CloseHandle( hThread );
		//if( g_hATP )
		//	FreeLibrary( g_hATP );
		break;
	}
	return TRUE;
}

