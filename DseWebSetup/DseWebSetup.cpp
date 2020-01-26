// DseWebSetup.cpp : Defines the entry point for the application.
//

#include "stdafx.h"
#include "DseWebSetup.h"
#include <winhttp.h>
#include "DlgWaitForDownload.h"
#pragma comment(lib,"winhttp.lib")

#define MAX_LOADSTRING 100

typedef BOOL (WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);


BOOL IsWow64()
{
    BOOL bIsWow64 = FALSE;
	LPFN_ISWOW64PROCESS fnIsWow64Process;

    fnIsWow64Process = (LPFN_ISWOW64PROCESS) GetProcAddress(
        GetModuleHandle(TEXT("kernel32")),"IsWow64Process");

    if(NULL != fnIsWow64Process)
    {
        if (!fnIsWow64Process(GetCurrentProcess(),&bIsWow64))
        {
            //handle error
        }
    }
    return bIsWow64;
}

bool GetTempPath( CString &strPath )
{
	TCHAR szTempPath[ 2048 ];
	if( !GetTempPath( MAX_PATH, szTempPath ) )
		return false;
	strPath = szTempPath;
	return true;
}

class CHttpAC
{
public:
	CHttpAC() : m_hInternet( NULL ) {}
	CHttpAC( HINTERNET hInternet ) : m_hInternet( hInternet )
	{}
	~CHttpAC()
	{
		if( m_hInternet )
			WinHttpCloseHandle( m_hInternet );
	}
	//operator bool() const throw() { return m_hInternet != NULL; }
	operator HINTERNET() const throw() { return m_hInternet; }
private:
	HINTERNET m_hInternet;
};

void GetServerResource( CString &strURL, CString &strServer, CString &strResource )
{
	int nPos = strURL.Find( _T("//") );
	if( nPos == -1 )
		return;
	nPos += 2;
	int nRes = strURL.Find( _T('/'), nPos );
	if( nRes == -1 )
		return;
	strServer.SetString( strURL.GetBuffer() + nPos, nRes - nPos );
	strResource = strURL.GetBuffer() + nRes;
}


static bool DownLoadFileWinHttpInternal( const CString &strURL,  const CString &strDest, const PCTSTR szProxy )
{

	CHttpAC hInternet;
	if( szProxy )
		hInternet = WinHttpOpen( L"Drainware Downloader", WINHTTP_ACCESS_TYPE_NAMED_PROXY, szProxy, WINHTTP_NO_PROXY_BYPASS, 0 );
	else
		hInternet = WinHttpOpen( L"Drainware Downloader", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0 );

	if( !hInternet )
		return false;

	CString strServer, strResource;
	GetServerResource( CString(strURL), strServer, strResource );

	CHttpAC hConnected = WinHttpConnect( hInternet, strServer, INTERNET_DEFAULT_HTTP_PORT, 0 );
	if( !hConnected )
		return false;

	CHttpAC hRequest = WinHttpOpenRequest( hConnected, L"GET", strResource, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_REFRESH );

	if( !hRequest )
		return false;

	WinHttpSetTimeouts( hInternet, 2000, 2000, 2000, 30000 );

	if( !WinHttpSendRequest( hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0 ) )
		return false;

	if ( !WinHttpReceiveResponse( hRequest, NULL ) )
		return false;

	CAtlFile f;
	f.Create( strDest, GENERIC_WRITE, FILE_SHARE_READ, CREATE_ALWAYS );
	if( !f )
		return false;

	DWORD dwSize = 0;

	do
	{
		if( !WinHttpQueryDataAvailable( hRequest, &dwSize ) )
			return false;
		if( dwSize )
		{
			PBYTE pBuffer = new BYTE[ dwSize + 1 ];
			if( pBuffer )
			{
				DWORD dwRead = 0;
				if( !WinHttpReadData( hRequest, pBuffer, dwSize, &dwRead ) )
				{
					delete [] pBuffer;
					return false;
				}

				f.Write( pBuffer, dwRead );
			}
			delete [] pBuffer;
		}
	}while( dwSize );

	return true;
}

bool DownLoadFileWinHttp( const CString &strURL,  const CString &strDest, const PCTSTR szProxy, bool bProxyEnable )
{
	if( szProxy && lstrlen( szProxy ) && bProxyEnable )
	{
		if( !DownLoadFileWinHttpInternal( strURL, strDest, szProxy ) )
			return DownLoadFileWinHttpInternal( strURL, strDest, NULL );
		return true;
	}
	else
	{
		if( !DownLoadFileWinHttpInternal( strURL, strDest, NULL ) )
		{
			if( szProxy && lstrlen(szProxy) )
				return DownLoadFileWinHttpInternal( strURL, strDest, szProxy );
			return false;
		}
		return true;
	}
}

void RunProcess( LPTSTR szFilePath, HANDLE *pHandle = NULL )
{
	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	ZeroMemory( &si, sizeof(si) );
	si.cb = sizeof(si);
	ZeroMemory( &pi, sizeof(pi) );

	BOOL bRet = CreateProcess( NULL, szFilePath, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi );
	if( !bRet )
	{
		DWORD dwError = GetLastError();
		dwError = 0;
	}
	if( pHandle )
		*pHandle = pi.hProcess;
	else
		CloseHandle( pi.hProcess );
	CloseHandle( pi.hThread );
}

// Forward declarations of functions included in this code module:

DWORD WINAPI ThreadDlg( PVOID pVoid )
{
	CWaitForDownload dlgWait;
	dlgWait.DoModal( GetActiveWindow() );
	return 0;
}

void LoadProxyInfo( CString &str, DWORD &nEnable )
{
	CRegKey rKey;
	if( ERROR_SUCCESS == rKey.Open( HKEY_CURRENT_USER, _T("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"), KEY_READ | KEY_WOW64_32KEY ) )
	{
		TCHAR szValue[ MAX_PATH ] = { 0 };
		ULONG nSize = MAX_PATH;
		if( ERROR_SUCCESS == rKey.QueryStringValue( _T("AutoConfigURL"), szValue, &nSize ) )
		{
			HINTERNET hInternet = WinHttpOpen( _T("TestProxy"), WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0 );
			if( hInternet )
			{
				WINHTTP_AUTOPROXY_OPTIONS opt = { 0 };
				WINHTTP_PROXY_INFO pInfo = { 0 };
				opt.dwFlags = WINHTTP_AUTOPROXY_CONFIG_URL;
				opt.dwAutoDetectFlags = WINHTTP_AUTO_DETECT_TYPE_DHCP | WINHTTP_AUTO_DETECT_TYPE_DNS_A;
				opt.lpszAutoConfigUrl = szValue;
				//opt.fAutoLogonIfChallenged = FALSE;
				if( WinHttpGetProxyForUrl( hInternet, _T("https://rabbot.drainware.com/"), &opt, &pInfo ) )
				{
					if( pInfo.lpszProxy )
					{
						str = pInfo.lpszProxy;
						::GlobalFree( pInfo.lpszProxy );
					}
					if( pInfo.lpszProxyBypass ) ::GlobalFree( pInfo.lpszProxyBypass );
					nEnable = 1;
				}
				else
				{
					DWORD dwError = GetLastError();
					dwError = 0;
				}

				WinHttpCloseHandle( hInternet );
			}

		}
		else
		{
			nSize = MAX_PATH;
			if( ERROR_SUCCESS == rKey.QueryStringValue( _T("ProxyServer"), szValue, &nSize ) )
			{
				rKey.QueryDWORDValue( _T("ProxyEnable"), nEnable );
				CString strProxy = szValue;
				CString strHttps;
				int nFind;
				if( ( nFind = strProxy.Find( _T("https=") ) ) != -1 )
				{
					int nEnd = strProxy.Find( _T(';'), nFind + 6 );
					if( nEnd == -1 )
						strHttps.SetString( strProxy.GetBuffer() + nFind + 6 );
					else
						strHttps.SetString( strProxy.GetBuffer() + nFind + 6, nEnd - nFind - 6 );
				}
				else if( ( nFind = strProxy.Find( _T("http=") ) ) != -1 )
				{
					int nEnd = strProxy.Find( _T(';'), nFind + 5 );
					if( nEnd == -1 )
						strHttps.SetString( strProxy.GetBuffer() + nFind + 5 );
					else
						strHttps.SetString( strProxy.GetBuffer() + nFind + 5, nEnd - nFind - 5 );
				}
				else strHttps = strProxy;
				str = strHttps;
			}
		}
	}
}

void LoadProxyList( const WCHAR *szProxyServer, CAtlArray<CString> &aProxy )
{
	CString str;
	str = szProxyServer;
	int nStartPos = 0;
	int nFind = str.Find( _T(';'), nStartPos );
	aProxy.RemoveAll();

	while( nFind != -1 )
	{
		CString &strNew = aProxy[ aProxy.Add() ];
		strNew.SetString( str.GetBuffer() + nStartPos, nFind - nStartPos );
		nStartPos = nFind + 1;
		nFind = str.Find( _T(';'), nStartPos );
	}

	aProxy[ aProxy.Add() ].SetString( str.GetBuffer() + nStartPos );
}


int APIENTRY _tWinMain(_In_ HINSTANCE hInstance,
                     _In_opt_ HINSTANCE hPrevInstance,
                     _In_ LPTSTR    lpCmdLine,
                     _In_ int       nCmdShow)
{
	UNREFERENCED_PARAMETER(hPrevInstance);
	UNREFERENCED_PARAMETER(lpCmdLine);
	UNREFERENCED_PARAMETER(hInstance);
	UNREFERENCED_PARAMETER(nCmdShow);

	CString strURL;
	CString strDest;
	GetTempPath( strDest );

	if( IsWow64() )
		strURL = _T("http://www.drainware.com/ddi/?module=cloud&action=downloadEndpoint&arch=64"),
		strDest += _T("DseSetup64.msi");
	else
		strURL =_T("http://www.drainware.com/ddi/?module=cloud&action=downloadEndpoint&arch=32"),
		strDest += _T("DseSetup32.msi");

	HANDLE hThread = CreateThread( NULL, 0, ThreadDlg, NULL, 0, NULL );


	CString strProxy;
	DWORD nEnable = 0;
	LoadProxyInfo( strProxy, nEnable );
	bool bDownload = false;
	if( strProxy.GetLength() )
	{
		CAtlArray<CString> aProxy;
		LoadProxyList( strProxy, aProxy );
		for( size_t i = 0; i < aProxy.GetCount(); i++ )
		{
			if( ( bDownload = DownLoadFileWinHttp( strURL, strDest, aProxy[ i ], true ) ) )
				break;
		}
	}
	else
		bDownload = DownLoadFileWinHttp( strURL, strDest, NULL, false );

	if( bDownload )
	{
		strDest.Insert( 0, _T("msiexec /i ") );
		//MessageBox( GetActiveWindow(), strDest, _T("msg"), 0 );
		RunProcess( strDest.GetBuffer() );
	}

	CWaitForDownload::m_bStop = true;
	if( WaitForSingleObject( hThread, 2000 ) == WAIT_TIMEOUT )
	{
		TerminateThread( hThread, 0 );
	}
	CloseHandle( hThread );


	return 0;
}



