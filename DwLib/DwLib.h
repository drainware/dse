#pragma once

class CAutoCS
{
public:
	CAutoCS( CCriticalSection &cs ) : m_cs( cs )
	{
		m_cs.Enter();
	}

	~CAutoCS()
	{
		m_cs.Leave();
	}
private:
CCriticalSection &m_cs;
};

void DwUnEscapeUrl( CStringA &strName );
void DwUnEscapeUrl( CString &strName );
void DwEscapeUrl( const CHAR *szName, CStringA &strName );
//void DwEscapeUrl( const TCHAR *szName, CString &strName );
//CStringA EscapeName( const CHAR *szName );
bool GetModuleDirectory( CString &strPath );
bool GetTempPath( CString &strPath );
bool GetTempFile( const LPCTSTR szTemplate, CAtlFile &f, CString &strFile );
BOOL IsWow64();
void RunProcess( LPTSTR szFilePath, HANDLE *pHandle = NULL );
void RunProcessAsUser( CAccessToken &token, LPTSTR szFilePath, HANDLE *pHandle = NULL );
CStringA DwBase64Decode( const char *szData, int nLength );
CStringA DwBase64Encode( const char *szData, int nLength );
bool FileExist( LPCTSTR szFileName );
bool IsDirectory( PCTSTR szPath );
bool IsDirectoryA( PCSTR szPath );
bool DownLoadFileWinHttp( const CString &strURL,  const CString &strDest, const PCTSTR szProxy = NULL, bool bProxyEnable = false );
bool DownLoadToBufferWinHttp( const CString &strURL,  CStringA &strDest, const PCTSTR szProxy = NULL, bool bProxyEnable = false );
bool QueryWinHttp( const CString &strURL, CStringA &strContent, int nPort = 80, CStringA *pstrPost = NULL, const PCTSTR szContentType = NULL, const PCTSTR szProxy = NULL, bool bProxyEnable = false );
void GetTimeNow( ULARGE_INTEGER &ul );

bool CompressXOR( CStringA &strComp );
bool UncompressXOR( CStringA &strComp );
bool GetRegKey( LPCTSTR szKey, CRegKey &rKey );
bool IsMappedDrive( PCTSTR szOrg, CString &strUNCPath );