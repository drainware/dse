#include "stdafx.h"
#include "DwLib.h"
#include <winhttp.h>
#include "..\..\drainwarelibs\zlib-1.2.7\zlib.h"
#include <atlutil.h>

#pragma comment(lib,"winhttp.lib")

#define INTERNET_OPTION_HTTP_DECODING 65

void DwEscapeUrl( const TCHAR *szName, CString &strName )
{
	CHAR szUTF8[ MAX_PATH ] = { 0 };
	CHAR szNameOut[ MAX_PATH ] = { 0 };
	DWORD dwOutLen = 0;
	AtlUnicodeToUTF8( szName, lstrlen(szName), szUTF8, MAX_PATH );
	if( AtlEscapeUrl( szUTF8, szNameOut, &dwOutLen,  MAX_PATH, ATL_URL_ESCAPE ) )
	{
		szNameOut[dwOutLen ] = 0;
		strName= szNameOut;
		CHAR szNameOut2[ MAX_PATH ] = { 0 };
		AtlUnescapeUrl( szNameOut, szNameOut2, &dwOutLen, MAX_PATH );
		szNameOut2[ dwOutLen ] = 0;
		TCHAR szOut[ MAX_PATH ] = { 0 };
		MultiByteToWideChar( CP_UTF8, 0, szNameOut2, lstrlenA(szNameOut2), szOut, MAX_PATH );
		int n = 0;
	}
	else
		strName = szName;
}

void DwEscapeUrl( const CHAR *szName, CStringA &strName )
{
	CString str, strOut;
	str = szName;
	DwEscapeUrl( str, strOut );
	strName = strOut;
}

void DwUnEscapeUrl( CStringA &strName )
{
	CHAR szOut[ MAX_PATH ];
	DWORD dwOutLen = 0;
	if( AtlUnescapeUrl( strName, szOut, &dwOutLen, MAX_PATH ) )
	{
		szOut[ dwOutLen ] = 0;
		TCHAR szOutw[ MAX_PATH ]= { 0 };
		MultiByteToWideChar( CP_UTF8, 0, szOut, lstrlenA(szOut), szOutw, MAX_PATH );
		strName = szOutw;
	}
}

void DwUnEscapeUrl( CString &strName )
{
	CStringA strA;
	strA = strName;
	DwUnEscapeUrl( strA );
	strName = strA;
}


//void DwEscapeUrl( const CHAR *szName, CStringA &strName )
//{
//	CHAR szNameOut[ MAX_PATH ] = { 0 };
//	DWORD dwOutLen = 0;
//	if( AtlEscapeUrl( szName, szNameOut, &dwOutLen,  MAX_PATH ) )
//	{
//		szNameOut[dwOutLen ] = 0;
//		strName= szNameOut;
//	}
//	else
//		strName = szName;
//}

CStringA EscapeName( const CHAR *szName )
{
	CStringA str;
	DwEscapeUrl( szName, str );
	return str;
}

bool GetModuleDirectory( CString &strPath )
{
	TCHAR szFilePath[ 2048 ];
	DWORD dwFLen = ::GetModuleFileName( NULL, szFilePath, 2048 );
	if( dwFLen == 0 || dwFLen == MAX_PATH )
		return false;

	strPath = szFilePath;
	int nFind = strPath.ReverseFind( _T('\\') );
	if( nFind == -1 )
		return false;
	strPath.Delete( nFind + 1, strPath.GetLength() - nFind - 1 );
	return true;
}

bool GetTempPath( CString &strPath )
{
	TCHAR szTempPath[ 2048 ];
	if( !GetTempPath( MAX_PATH, szTempPath ) )
		return false;
	strPath = szTempPath;
	return true;
}

bool GetTempFile( const LPCTSTR szTemplate, CAtlFile &f, CString &strFile )
{
	int nTemp = 0;
	CString strTemp;
	GetTempPath( strTemp );
	strTemp += szTemplate;
	while( true )
	{
		strFile.Format( strTemp, nTemp );
		if( S_OK == f.Create( strFile, GENERIC_WRITE, FILE_SHARE_READ, CREATE_ALWAYS ) )
			break;
		++nTemp;
	}
	return true;
}

typedef BOOL (WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);

LPFN_ISWOW64PROCESS fnIsWow64Process;

BOOL IsWow64()
{
    BOOL bIsWow64 = FALSE;

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

void RunProcess( LPTSTR szFilePath, HANDLE *pHandle )
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

void RunProcessAsUser( CAccessToken &token, LPTSTR szFilePath, HANDLE *pHandle )
{
	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	ZeroMemory( &si, sizeof(si) );
	si.cb = sizeof(si);
	ZeroMemory( &pi, sizeof(pi) );

	
	BOOL bRet = CreateProcessAsUser( token.GetHandle(), NULL, szFilePath, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi );
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

CStringA DwBase64Decode( const char *szData, int nLength )
{
	int nDecodedLength = Base64DecodeGetRequiredLength( nLength );
	char *pDest = new char[ nDecodedLength + 1 ];
	if( !Base64Decode( szData, nLength, (PBYTE)pDest, &nDecodedLength ) )
	{
		delete [] pDest;
		pDest = new char[ nDecodedLength + 1 ];
		Base64Decode( szData, nLength, (PBYTE)pDest, &nDecodedLength );
	}
	pDest[ nDecodedLength ] = 0;
	CStringA strRet = pDest;
	delete [] pDest;
	return strRet;
}

CStringA DwBase64Encode( const char *szData, int nLength )
{
	int nDestLen = Base64EncodeGetRequiredLength( nLength );
	char *pDest = new char[ nDestLen + 1 ];

	if( !Base64Encode( (const BYTE *)szData, nLength, pDest, &nDestLen ) )
	{
		delete [] pDest;
		pDest = new char[ nDestLen + 1 ];
		Base64Encode( (const BYTE *)szData, nLength, pDest, &nDestLen );
	}
	pDest[ nDestLen ] = 0;
	CStringA strDest = pDest;
	delete [] pDest;
	return strDest;
}

bool FileExist( LPCTSTR szFileName )
{
	return !(GetFileAttributes( szFileName ) == INVALID_FILE_ATTRIBUTES);
}

bool IsDirectory( PCTSTR szPath )
{
	DWORD dwAttr;
	if( ( dwAttr = ::GetFileAttributes( szPath ) ) != INVALID_FILE_ATTRIBUTES )
	{
		if( dwAttr & FILE_ATTRIBUTE_DIRECTORY )
			return true;
	}
	return false;
}

bool IsDirectoryA( PCSTR szPath )
{
	DWORD dwAttr;
	if( ( dwAttr = ::GetFileAttributesA( szPath ) ) != INVALID_FILE_ATTRIBUTES )
	{
		if( dwAttr & FILE_ATTRIBUTE_DIRECTORY )
			return true;
	}
	return false;
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
	void operator=( HINTERNET hInternet ) { m_hInternet = hInternet; }
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

static bool DownLoadToBufferWinHttpInternal( const CString &strURL,  CStringA &strDest, const PCTSTR szProxy )
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

	CHttpAC hConnected = WinHttpConnect( hInternet, strServer, INTERNET_DEFAULT_HTTPS_PORT, 0 );
	if( !hConnected )
		return false;

	CHttpAC hRequest = WinHttpOpenRequest( hConnected, L"GET", strResource, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_REFRESH | WINHTTP_FLAG_SECURE );

	if( !hRequest )
		return false;

	WinHttpSetTimeouts( hInternet, 2000, 2000, 2000, 30000 );
	//BOOL bEncoding = TRUE;
	//WinHttpSetOption( hInternet, INTERNET_OPTION_HTTP_DECODING, &bEncoding, sizeof(BOOL) );

	if( !WinHttpSendRequest( hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0 ) )
	{
		DWORD dwError = GetLastError();
		return false;
	}

	if ( !WinHttpReceiveResponse( hRequest, NULL ) )
		return false;


	strDest.Empty();
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
				int nLen = strDest.GetLength();
				CopyMemory( strDest.GetBufferSetLength( nLen + int(dwRead) ) + nLen, pBuffer, dwRead );
			}
			delete [] pBuffer;
		}
	}while( dwSize );

	return true;
}

bool DownLoadToBufferWinHttp( const CString &strURL,  CStringA &strDest, const PCTSTR szProxy, bool bProxyEnable )
{
	if( szProxy && lstrlen( szProxy ) && bProxyEnable )
	{
		if( !DownLoadToBufferWinHttpInternal( strURL, strDest, szProxy ) )
			return DownLoadToBufferWinHttpInternal( strURL, strDest, NULL );
		return true;
	}
	else
	{
		if( !DownLoadToBufferWinHttpInternal( strURL, strDest, NULL ) )
		{
			if( szProxy && lstrlen(szProxy) )
				return DownLoadToBufferWinHttpInternal( strURL, strDest, szProxy );
			return false;
		}
		return true;
	}
}

static bool QueryWinHttpInternal( const CString &strURL, CStringA &strContent, int nPort, CStringA *pstrPost, const PCTSTR szContentType, const PCTSTR szProxy )
{
	CHttpAC hInternet;
	if( szProxy )
		hInternet = WinHttpOpen( L"User-Agent: Mozilla 5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.0.11)", WINHTTP_ACCESS_TYPE_NAMED_PROXY, szProxy, WINHTTP_NO_PROXY_BYPASS, 0 );
	else
		hInternet = WinHttpOpen( L"User-Agent: Mozilla 5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.0.11)", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0 );

	CString strServer, strResource;
	GetServerResource( CString(strURL), strServer, strResource );

	CHttpAC hConnected = WinHttpConnect( hInternet, strServer, nPort, 0 );
	if( !hConnected )
		return false;

	DWORD dwFlags = WINHTTP_FLAG_REFRESH;
	if( nPort == 443 || strURL.Find( _T("https") ) != -1 )
		dwFlags |= WINHTTP_FLAG_SECURE;

	CHttpAC hRequest = WinHttpOpenRequest( hConnected, pstrPost ? L"POST" : L"GET", strResource, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, dwFlags );

	if( !hRequest )
		return false;


	//if( !WinHttpSendRequest( hRequest, szContentType, -1L, strPost.GetBuffer(), strPost.GetLength(), strPost.GetLength(), 0 ) )
	//{
	//	DWORD dwError = GetLastError();
	//	return false;
	//}
	WinHttpSetTimeouts( hInternet, 2000, 2000, 2000, 30000 );
	if( pstrPost )
	{
		CString strHeaders;
		strHeaders.Format( _T("Content-Type: %s\r\nContent-Length: %d\r\n"), szContentType, pstrPost->GetLength() );
		if( !WinHttpSendRequest( hRequest, strHeaders, strHeaders.GetLength(), pstrPost->GetBuffer(), pstrPost->GetLength(), pstrPost->GetLength(), 0 ) )
		{
			//DWORD dwError = GetLastError();
			return false;
		}
	}
	else
	if( !WinHttpSendRequest( hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0 ) )
		return false;

	if ( !WinHttpReceiveResponse( hRequest, NULL ) )
		return false;

	DWORD dwSize = 0;
	strContent.Empty();
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

				//f.Write( pBuffer, dwRead );
				int nLength = strContent.GetLength();
				CopyMemory( strContent.GetBufferSetLength( nLength + dwRead ) + nLength, pBuffer, dwRead );
			}
			delete [] pBuffer;
		}
	}while( dwSize );

	return true;
}

bool QueryWinHttp( const CString &strURL, CStringA &strContent, int nPort, CStringA *pstrPost, const PCTSTR szContentType, const PCTSTR szProxy, bool bProxyEnable )
{
	if( szProxy && lstrlen( szProxy ) && bProxyEnable )
	{
		if( !QueryWinHttpInternal( strURL, strContent, nPort, pstrPost, szContentType, szProxy ) )
			return QueryWinHttpInternal( strURL, strContent, nPort, pstrPost, szContentType, NULL );
		return true;
	}
	else
	{
		if( !QueryWinHttpInternal( strURL, strContent, nPort, pstrPost, szContentType, NULL ) )
		{
			if( szProxy && lstrlen(szProxy) )
				return QueryWinHttpInternal( strURL, strContent, nPort, pstrPost, szContentType, szProxy );
			return false;
		}
		return true;
	}
}

void GetTimeNow( ULARGE_INTEGER &ul )
{
	SYSTEMTIME st;
	FILETIME ft;

	GetSystemTime( &st );
	SystemTimeToFileTime( &st, &ft );
	ul.HighPart = ft.dwHighDateTime;
	ul.LowPart = ft.dwLowDateTime;
}


static int Compress( PBYTE pDest, ULONG *puDestSize, const PBYTE pSource, ULONG nSourceSize, int nCompressLevel )
{
	compress2( pDest, puDestSize, pSource, nSourceSize, nCompressLevel );
}

const BYTE nKey = 0xde;

const void XORBuffer( PBYTE pBuffer, int nSize )
{
	for( int i = 0; i < nSize; i++ )
		pBuffer[ i ] ^= nKey;
}

bool CompressXOR( CStringA &strComp )
{
	CStringA strDest;
	ULONG nDestSize = strComp.GetLength() + 128;
	compress2( (Bytef*)strDest.GetBufferSetLength( nDestSize ), &nDestSize, (Bytef*)strComp.GetBuffer(), strComp.GetLength(), 6 );
	strDest.Truncate( nDestSize );
	XORBuffer( (PBYTE)strDest.GetBuffer(), strDest.GetLength() );
	CopyMemory( strComp.GetBufferSetLength( nDestSize ), strDest.GetBuffer(), nDestSize );
	return true;
}

bool UncompressXOR( CStringA &strComp )
{
	const ULONG nMemoryLimit = 1024 * 1024 * 16; //16Mb
	XORBuffer( (PBYTE)strComp.GetBuffer(), strComp.GetLength() );
	CStringA strDest;
	ULONG nSize = strComp.GetLength() * 10;


	int nLastError;
	while( Z_BUF_ERROR == ( nLastError = ::uncompress( (const PBYTE)strDest.GetBufferSetLength( nSize ), &nSize, (const PBYTE)strComp.GetBuffer(), strComp.GetLength() ) ) && nSize <= nMemoryLimit )
		nSize *= 2;
	if( nSize >= nMemoryLimit || nLastError != Z_OK )
		return false;

	CopyMemory( strComp.GetBufferSetLength( nSize ), strDest.GetBuffer(), nSize );
	return true;
}

bool GetRegKey( LPCTSTR szKey, CRegKey &rKey )
{
	if( ERROR_SUCCESS != rKey.Open( HKEY_LOCAL_MACHINE, szKey, KEY_READ | KEY_WRITE ) )
	{
		if( ERROR_SUCCESS != rKey.Create( HKEY_LOCAL_MACHINE, szKey, NULL, 0, KEY_READ | KEY_WRITE ) )
		{
			DWORD dwErr = GetLastError();
			return false;
		}
	}
	return true;
}

bool IsMappedDrive( PCTSTR szOrg, CString &strUNCPath )
{
	if( !szOrg || szOrg[ 0 ] == _T('\\') )
		return false;
	TCHAR szDrive[] = _T("X:\\");
	szDrive[ 0 ] = szOrg[ 0 ];
	if( GetDriveType( szDrive ) == DRIVE_REMOTE )
	{
		szDrive[ 2 ] = 0;
		TCHAR szRemote[ 4096 ];
		DWORD dwLength = 4096;
		DWORD dwError = WNetGetConnection( szDrive, szRemote, &dwLength );
		if( NO_ERROR == dwError )
		{
			strUNCPath = szRemote;
			if( strUNCPath.GetLength() && strUNCPath[ strUNCPath.GetLength() - 1 ] != _T('\\') )
				strUNCPath += _T('\\');
			strUNCPath += ( szOrg + 3 );
			return true;
		}
	}

	return false;
}
