// DwUserAgent.cpp: implementación de WinMain


#include "stdafx.h"
#include "resource.h"
#include "DwUserAgent_i.h"
#include "DriveWatcher.h"
#include "WndUserAgent.h"
#include "../DwLib/DwLib.h"

//CEvent g_evt;
CString strFileName;
bool g_bExit = false;


static DWORD WINAPI ThreadCheckUpdated( LPVOID pVoid )
{
	WIN32_FILE_ATTRIBUTE_DATA wfad = { 0 };

	if( GetFileAttributesEx( strFileName, GetFileExInfoStandard, &wfad ) )
	{
		WIN32_FILE_ATTRIBUTE_DATA wfad2 = { 0 };
		int n =  0;
		while( true )
		{
			Sleep( 2000 );
			++n;
			if( !GetFileAttributesEx( strFileName, GetFileExInfoStandard, &wfad2 ) )
				return 1;

			//After 5 minutes restart any of the userAgent
			if( n > 150 || memcmp( &wfad.ftCreationTime, &wfad2.ftCreationTime, sizeof( FILETIME ) ) || memcmp( &wfad.ftLastWriteTime, &wfad2.ftLastWriteTime, sizeof( FILETIME ) ) ||
				wfad.nFileSizeLow != wfad2.nFileSizeLow )
			{
				Sleep( 50000 ); //Give fifty seconds to ensure that all files are updated including the service
				RunProcess( strFileName.GetBuffer() );
				return 0;
			}

		}

	}

	return 0;
}

//#include "LicenseDlg.h"

class CDwUserAgentModule : public ATL::CAtlExeModuleT< CDwUserAgentModule >
{
public :

	typedef ATL::CAtlExeModuleT< CDwUserAgentModule > _Base;

	DECLARE_LIBID(LIBID_DwUserAgentLib)
	DECLARE_REGISTRY_APPID_RESOURCEID(IDR_DWUSERAGENT, "{01EA8580-63AB-487E-B541-7724B7DBEDB4}")

	HRESULT Run(_In_ int nShowCmd = SW_HIDE)
	{
		//CoInitializeEx( NULL, COINIT_MULTITHREADED );
		//CLicenseDlg dlg;
		//dlg.DoModal();
		int nArgs = 0;
		LPWSTR *pArgv = CommandLineToArgvW( GetCommandLine(), &nArgs );
		HRESULT hRet = S_OK;

		if( pArgv && nArgs > 1 && PathFileExists( pArgv[ 1 ] ) )
		{
			strFileName = pArgv[ 1 ];
			HANDLE hThread = ::CreateThread( NULL, 0, ThreadCheckUpdated, reinterpret_cast<PVOID>(this), 0, NULL );
			WaitForSingleObject( hThread, INFINITE );
			return 0;
		}

		CoInitializeEx( NULL, COINIT_MULTITHREADED );

		HRESULT hr = CoInitializeSecurity( NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_NONE, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL );
		//HRESULT hr = CoInitializeSecurity( NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_NONE, RPC_C_IMP_LEVEL_IDENTIFY, NULL, EOAC_NONE, NULL );
		
		TCHAR szFilePath[ MAX_PATH ];
		::GetModuleFileName(NULL, szFilePath, MAX_PATH);

		//ITypeLib* pTLib = NULL;
		//hr = LoadTypeLibEx( szFilePath, REGKIND_REGISTER, &pTLib );
		//if( pTLib )
		//	pTLib->Release();

		CComObject<CWndUserAgent> *wndUserAgent;
		CComObject<CWndUserAgent>::CreateInstance( &wndUserAgent );
		wndUserAgent->AddRef();
		if( wndUserAgent->Create( NULL, ATL::CWindow::rcDefault, _T("Drainware User Agent"), WS_OVERLAPPEDWINDOW ) )
			hRet = _Base::Run( nShowCmd );
		wndUserAgent->Release();
		CoUninitialize();
		return hRet;
	}
private:
};

CDwUserAgentModule _AtlModule;

TCHAR szFilePath[ 2048 ];

LONG WINAPI UnhandledExceptionFilterDw( struct _EXCEPTION_POINTERS *ExceptionInfo )
{
	RunProcess( szFilePath );
	::ExitProcess( 0 );
	return 0;
}

//
extern "C" int WINAPI _tWinMain(HINSTANCE /*hInstance*/, HINSTANCE /*hPrevInstance*/, 
								LPTSTR /*lpCmdLine*/, int nShowCmd)
{
	::GetModuleFileName( NULL, szFilePath, 2048 );
	SetUnhandledExceptionFilter( UnhandledExceptionFilterDw );

	return _AtlModule.WinMain(nShowCmd);
}

