#include "stdafx.h"
#include "DriveWatcher.h"
#include "WndUserAgent.h"
#include "..\DrainwareSecurityAgent\DrainwareSecurityAgent_i.c"
#include "..\DwLib\DwLib.h"
#include "..\DwLib\DseVersion.h"
#include "LicenseDlg.h"
#include "resource.h"
//#include <atlhttp.h>
#include <GdiPlus.h>
#include "WaitForCheck.h"
#include "UserMessage.h"
#include <ioevent.h>
#include <Psapi.h>
//#include <usbiodef.h>
#include <winhttp.h>

#pragma comment( lib, "Winhttp.lib" )
#pragma comment( lib, "gdiplus" )
#pragma comment(lib, "Msimg32.lib")
#pragma comment(lib, "Psapi.lib" )
#pragma comment(lib, "version.lib")


using namespace Gdiplus;

// {BD93B62A-ACE5-4E85-9D33-57B09B5E8A54}
static const GUID GUID_IO_MEDIA_REMOVAL_DW = 
{ 0xd07433c1, 0xa98e, 0x11d2, { 0x91, 0x7a, 0x00, 0xa0, 0xc9, 0x06, 0x8f, 0xf3 } };

static const GUID GUID_IO_VOLUME_LOCK_DW = 
{ 0x50708874L, 0xc9af, 0x11d1, { 0x8f, 0xef, 0x00, 0xa0, 0xc9, 0xa0, 0x6d, 0x32 } };


CAtlMap< CString, CString > g_mapDevices;
void LoadDeviceNames()
{
	
	TCHAR szDeviceName[ MAX_PATH ] = _T("");
	TCHAR szVolumeName[ MAX_PATH ] = _T("");
	TCHAR szPath[ MAX_PATH ] = _T("");
	HANDLE hFind = FindFirstVolume( szVolumeName, MAX_PATH );

	while( true )
	{
		int nLast = lstrlen( szVolumeName ) - 1;
		szVolumeName[ nLast ] = 0;
		QueryDosDevice( &szVolumeName[ 4 ], szDeviceName, MAX_PATH );
		szVolumeName[ nLast ] = _T('\\');
		DWORD dwLen;
		GetVolumePathNamesForVolumeName( szVolumeName, szPath, MAX_PATH, &dwLen );
		//szPath[ lstrlen( szPath ) - 1 ] = 0;
		g_mapDevices[ szDeviceName ] = szPath;

		if( !FindNextVolume( hFind, szVolumeName, MAX_PATH ) )
			break;
	}
}

bool NormalizePath( CString &strRes )
{
	if( strRes.Find( _T("\\Device\\Mup\\") ) == 0 )
	{
		strRes.Delete( 0, 10 );
		strRes.SetAt( 0, _T('\\') );
	}
	else if( strRes.Find( _T("\\Device\\LanmanRedirector\\") ) == 0 )
	{
		strRes.Delete( 0, 24 );
		strRes.SetAt( 0, _T('\\') );
	}
	else if( strRes.Find( _T("\\Device\\") ) == 0 )
	{
		int nPos = strRes.Find( _T('\\'), 8 );
		if( nPos != -1 )
		{
			CString str;
			str.SetString( strRes, nPos );
			CAtlMap< CString, CString >::CPair *pPair = g_mapDevices.Lookup( str );
			if( pPair )
			{
				strRes.Delete( 0, nPos + 1 );
				strRes.Insert( 0, pPair->m_value );
				return true;
			}
		}
	}
	return false;
}

static int GetEncoderClsid( const WCHAR* format, CLSID* pClsid )
{
	UINT  num = 0;          // number of image encoders
	UINT  size = 0;         // size of the image encoder array in bytes

	ImageCodecInfo* pImageCodecInfo = NULL;

	GetImageEncodersSize(&num, &size);
	if(size == 0)
		return -1;  // Failure

	pImageCodecInfo = (ImageCodecInfo*)(malloc(size));
	if(pImageCodecInfo == NULL)
		return -1;  // Failure

	GetImageEncoders(num, size, pImageCodecInfo);

	for(UINT j = 0; j < num; ++j)
	{
		if( wcscmp(pImageCodecInfo[j].MimeType, format) == 0 )
		{
			*pClsid = pImageCodecInfo[j].Clsid;
			free(pImageCodecInfo);
			return j;  // Success
		}    
	}

	free(pImageCodecInfo);
	return -1;  // Failure
}

static void GetFileDescription( TCHAR *szPath, CString &strName )
{
	DWORD dwDummy = 0;
	CString strPath = szPath;
	NormalizePath( strPath );
	DWORD dwSize = GetFileVersionInfoSize( strPath, &dwDummy );
	strName.Empty();
	if( dwSize )
	{
		BYTE *pBuffer = new BYTE[ dwSize + 2 ];
		if( pBuffer )
		{
			if( GetFileVersionInfo( strPath, dwDummy, dwSize, pBuffer ) )
			{
				pBuffer[ dwSize ] = pBuffer[ dwSize + 1 ] = 0;
				WCHAR *szOriginalFilename = L"FileDescription";
				int nSize = 16 * sizeof(WCHAR);
				int nTotal = dwSize - nSize;
				BYTE *pSrc = pBuffer;
				for( int i = 0; i < nTotal; i++ )
				{
					if( !lstrcmp( szOriginalFilename, (WCHAR*)pSrc ) )
					{
						pSrc += nSize + sizeof( WCHAR );
						strName = (WCHAR*)pSrc;
						break;
					}
					else
						++pSrc;
				}
			}
			delete [] pBuffer;
		}
	}
}

static void GetProcessAndUserName( ULONG nPid, CString &strName, CString &strFileDesc )
{
	strName.Empty();
	HANDLE hProc = OpenProcess( PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, nPid );
	if( hProc )
	{
		TCHAR szName[ 1024 ];
		DWORD dwSize = 1024;
		//QueryFullProcessImageName( hProc, 0, szName, &dwSize );
		GetProcessImageFileName( hProc, szName, 1024 );
		GetFileDescription( szName, strFileDesc );
		TCHAR *pProcName = StrRChr( szName, NULL, L'\\' );
		strName = pProcName ? pProcName + 1 : szName;
		CloseHandle( hProc );
	}
}


CString GetForegroundAppName() //Now returns JSON with process info
{
	CString strJSON = _T("{");
	HWND hWnd = GetForegroundWindow();
	if( hWnd )
	{
		int nLen = ::GetWindowTextLength( hWnd );
		CString str;
		::GetWindowText( hWnd, str.GetBufferSetLength( nLen + 1 ), nLen + 1 );
		DWORD dwPID = 0;
		GetWindowThreadProcessId( hWnd, &dwPID );
		if( dwPID )
		{
			CString strName, strDesc;
			GetProcessAndUserName( dwPID, strName, strDesc );
			//process_name:iexplorer.exe, description:'Internet Explorer', details:
			strJSON += _T(" \"process_name\":\""); strJSON += strName; 
			strJSON += _T("\", \"description\":\""); strJSON += strDesc;
			strJSON += _T("\",");
		}
		strJSON += _T("\"details\":\""); strJSON += str; strJSON += _T("\"");

	}
	strJSON += _T(" }");
	return strJSON;
}

static void GetBitmapSize( HBITMAP hBmp, SIZE &sz )
{
	DIBSECTION ds = { 0 };
	if( GetObject( hBmp, sizeof(ds), &ds ) )
	{
		sz.cx = ds.dsBm.bmWidth;
		sz.cy = ds.dsBm.bmHeight;
		return;
	}
	BITMAP bm = { 0 };
	if( GetObject( hBmp, sizeof(bm), &bm ) )
	{
		sz.cx = bm.bmWidth;
		sz.cy = bm.bmHeight;
		return;
	}

	BITMAPCOREHEADER bch = { 0 };
	bch.bcSize = sizeof(bch);
	HDC hDC = CreateCompatibleDC( NULL );
	GetDIBits( hDC, hBmp, 0, 0, NULL, reinterpret_cast<PBITMAPINFO>(&bch), DIB_RGB_COLORS );
	DWORD dwError = GetLastError();
	DeleteDC( hDC );
	sz.cx = bch.bcWidth;
	sz.cy = bch.bcHeight;

	//BITMAPINFOHEADER bmih = { 0 };
	//bmih.biSize = sizeof( BITMAPINFOHEADER );
	//HDC hDC = ::GetDC( NULL );
	//GetDIBits( hDC, hBmp, 0, 0, NULL, reinterpret_cast<PBITMAPINFO>(&bmih), DIB_RGB_COLORS );
	//::ReleaseDC( NULL, hDC );
	//sz.cx = bmih.biWidth;
	//sz.cy = bmih.biHeight;
}

static HBITMAP CreateBitmap24( int cx, int cy, PVOID &pVoid )
{
	BITMAPINFOHEADER bmih = { 0 };
	bmih.biSize = sizeof( BITMAPINFOHEADER );
	bmih.biWidth = cx, bmih.biHeight = cy;
	bmih.biPlanes = 1;
	bmih.biBitCount = 24;
	bmih.biCompression = BI_RGB;
	HDC hDC = CreateCompatibleDC( NULL );
	HBITMAP hBmp = CreateDIBSection( hDC, reinterpret_cast<PBITMAPINFO>(&bmih), DIB_RGB_COLORS, &pVoid, NULL, 0 );
	DeleteDC( hDC );
	return hBmp;
}

Crc32 CWndUserAgent::m_crc32;

CWndUserAgent::CWndUserAgent() : m_dwCookie( 0 ), m_thCheck( NULL ), m_thProxy( NULL ), m_hDevNotify( NULL ), m_pt( 0 ), m_bInitialized( false ), m_hBmpCopy( NULL ),
	m_bCheckingOCR( false )
{
	m_evtOCR.Create( NULL, FALSE, FALSE, NULL );
	m_evtProxy.Create( NULL, FALSE, FALSE, NULL );
	CWndClassInfo &wi = GetWndClassInfo();
	wi.m_wc.hIcon = (HICON)LoadImage( NULL, MAKEINTRESOURCE( IDI_ICON_APP ), IMAGE_ICON, 32, 32, LR_SHARED );
	wi.m_wc.hIconSm = (HICON)LoadImage( NULL, MAKEINTRESOURCE( IDI_ICON_APP ), IMAGE_ICON, 16, 16, LR_SHARED );

	HBITMAP hBmpRes = (HBITMAP)::LoadImage( GetModuleHandle( NULL ), MAKEINTRESOURCE(IDB_DRAINWARELOGO), IMAGE_BITMAP, 0, 0, LR_DEFAULTCOLOR );
	HDC hDC = CreateCompatibleDC( NULL );
	HBITMAP hBmpOld = (HBITMAP)SelectObject( hDC, hBmpRes );
	SIZE sz;
	GetBitmapSize( hBmpRes, sz );

	PVOID pBits = NULL;
	HBITMAP hBmpDrainware = CreateBitmap24( sz.cx, sz.cy, pBits );
	HDC hdcDst = CreateCompatibleDC( NULL );
	HBITMAP hBmpOld2 = (HBITMAP)SelectObject( hdcDst, hBmpDrainware );
	
	BitBlt( hdcDst, 0, 0, sz.cx, sz.cy, hDC, 0, 0, SRCCOPY );

	m_crcDrainware = m_crc32( (PBYTE)pBits, sz.cx * sz.cy * 3 );
	
	SelectObject( hdcDst, hBmpOld2 );
	SelectObject( hDC, hBmpOld );
	DeleteObject( hBmpDrainware );
	DeleteObject( hBmpRes );
	DeleteDC( hdcDst );
	DeleteDC( hDC );
}

CWndUserAgent::~CWndUserAgent()
{
	//if( m_hBmpCopy )
	//	DeleteObject( m_hBmpCopy );
}

bool CWndUserAgent::DownloadFile( const CString &strUrl, CStringA &str )
{
	//CAtlHttpClient cli;
	//if( cli.Navigate( strUrl, (ATL_NAVIGATE_DATA*)NULL ) )
	//{
	//	if( cli.GetStatus() == 200 )
	//	{
	//		CopyMemory( str.GetBufferSetLength( cli.GetBodyLength() ), cli.GetBody(), cli.GetBodyLength() );
	//		return true;
	//	}
	//}
	return DownLoadToBufferWinHttp( strUrl, str );
}


void CWndUserAgent::CheckForProxy()
{
	CString strProxy;
	while( WaitForSingleObject( m_evtProxy, 60 * 1000 ) == WAIT_TIMEOUT )
	{
		DWORD nEnable = 0;
		LoadProxyInfo( strProxy, nEnable );
		if( strProxy.GetLength() && strProxy != m_strProxy )
		{
			m_strProxy = strProxy;
			m_SrvMngr.AddProxy( CComBSTR( m_strProxy ), nEnable );
		}
	}
}

bool CWndUserAgent::CheckForUpdates()
{
	CStringA strText;
	BOOL bIsCloud = m_pt & PROTECT_CLOUD;
#ifdef _DW64_
	CString strUpdateURL;
	strUpdateURL.Format( _T("http://update.drainware.com/latest-dse/?current_version=%02d.%02d.%02d.%02d"), DWMAJORVERSION, DWMINORRVERSION, DWBUILDVERSION, DWPATCHVERSION );
	if( bIsCloud )
		strUpdateURL += _T("&mode=cloud");
	if( DownloadFile( strUpdateURL, strText ) )
#else
	CString strUpdateURL;
	strUpdateURL.Format( _T("http://update.drainware.com/latest-dse/?current_version=%02d.%02d.%02d.%02d&arch=32"), DWMAJORVERSION, DWMINORRVERSION, DWBUILDVERSION, DWPATCHVERSION );
	if( bIsCloud )
		strUpdateURL += _T("&mode=cloud");
	if( DownloadFile( strUpdateURL, strText ) )
#endif
	{
		int aVer[ 4 ];
		int aCurVer[ 4 ] = { 1, 0, 0, 1 };

		sscanf_s( strText, "%d.%d.%d.%d", &aVer[ 0 ], &aVer[ 1 ], &aVer[ 2 ], &aVer[ 3 ], strText.GetLength() );

		bool bDownload = false;
		for( int i = 0; i < 4; i++ )
		{
			if( aVer[ i ] > aCurVer[ i ] )
			{
				bDownload = true;
				break;
			}
			else
				if( aVer[ i ] < aCurVer[ i ] )
					break;
		}

		if( bDownload )
		{
			int nFind = strText.Find( '\n' );
			if( nFind != -1 )
			{
				CStringA strUrl = strText.GetBuffer() + nFind + 1;
				CStringA strMSI;
				strUrl.TrimRight( '\n' );
				if( DownloadFile( CString(strUrl), strMSI ) )
				{
					TCHAR szTempPath[ MAX_PATH ];
					GetTempPath( MAX_PATH, szTempPath );
					int nPos = strUrl.ReverseFind( '/' );
					if( nPos != -1 )
					{
						CString strFileName = szTempPath;
						strFileName += strUrl.GetBuffer() + nPos + 1;
						CAtlFile f;
						f.Create( strFileName, GENERIC_WRITE, FILE_SHARE_READ, CREATE_ALWAYS );
						if( f )
						{
							f.Write( strMSI.GetBuffer(), strMSI.GetLength() );
							//TODO Put parameters for /silent and /update
							ShellExecute( GetActiveWindow(), NULL, strFileName, NULL, NULL, SW_SHOWNORMAL );
							return true;
						}
					}
				}
			}
		}
	}
	return false;
}


void CWndUserAgent::LoadProxyInfo( CString &str, DWORD &nEnable )
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

LRESULT CWndUserAgent::OnCreate( UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL& bHandled )
{
	m_nCheckType = TYPE_INITIALIZE;

	CString strPath;
	GetModuleDirectory( strPath );
	strPath += _T("sftt.tmp");
	bool bShowDlg = !FileExist( strPath );

	if( bShowDlg )
		m_thCheck = CreateThread( NULL, 0, ThreadDlg, PVOID(this), 0, NULL );

	if( !m_SrvMngr.Init( GetUnknown() ) )
	{
		MessageBox( _T("Error connecting to Drainware Service"), _T("Call to drainware support center"), MB_ICONERROR );
		return -1;
	}

	if( bShowDlg )
		CloseCheckDlg();
	LoadDeviceNames();
	//CheckForUpdates();
	//Check if License is correct

	//Sleep( 25000 );
	//CString strProxy;
	DWORD nEnable = 0;
	LoadProxyInfo( m_strProxy, nEnable );
	if( m_strProxy.GetLength() )
		m_SrvMngr.AddProxy( CComBSTR( m_strProxy ), nEnable );

	m_thProxy = CreateThread( NULL, 0, ThreadProxy, PVOID(this), 0, NULL );
	

	VARIANT_BOOL bLic = VARIANT_FALSE;
	HRESULT hr = m_SrvMngr.IsLicensed( &bLic );
	if(  hr == S_OK && bLic == VARIANT_FALSE )
	{
		while( true )
		{
			CLicenseDlg dlg;
			if( dlg.DoModal() == IDOK )
			{
				LONG nCode = 0;
				CComBSTR bstrUrl;
				m_SrvMngr.SetLicense( dlg.m_strLic1, dlg.m_strLic2, dlg.m_strLic3, dlg.m_strLic4, &bstrUrl, &nCode );
				//if( bstrUrl.Length() )
				//	ShellExecute( NULL, NULL, bstrUrl, NULL, NULL, SW_SHOWNORMAL );
				CString strAlert;
				CString strError;
				if( nCode >= 0 )
				{
					strAlert.LoadString( IDS_LICENSE_OK );
					strError.LoadString( IDS_INFO );
					MessageBox( strAlert, strError );
					break;
				}
				else
				{
					CString strAlert;
					strAlert.LoadString( IDS_BAD_LICENSE );
					strError.LoadString( IDS_ERROR );
					MessageBox( strAlert, strError );
				}
			}
			else
			{
				return -1;
			}
		}
	}

	m_SrvMngr.MonitorProcess();
	m_wndTray.Create( NULL, CRect( 0, 0, 260, 64 + 24 + 4 ), _T("Drainware Tray Message"), WS_POPUP, WS_EX_TOOLWINDOW | WS_EX_LAYERED );
	m_wndTray.UpdateWindow();

	GdiplusStartupInput gpsi;
	ULONG_PTR nToken;
	GdiplusStartup( &nToken, &gpsi, NULL );

	GetEncoderClsid( L"image/jpeg", &m_clsidJpeg );

	GdiplusShutdown( nToken );

	ULONG pt;
	m_SrvMngr.GetProtectionType( &pt );
	UpdateModuleConfig( pt );
	m_bInitialized = true;

	SetErrorMode( SEM_FAILCRITICALERRORS );
	m_hWndNextCBViewer = SetClipboardViewer();


	//HRESULT hr = CoGetClassObject( IID_IDwService, CLSCTX_LOCAL_SERVER, NULL, IID_IDwService, (void**)&m_pDwService );
	return 0;
}

LRESULT CWndUserAgent::OnDestroy( UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL& bHandled )
{
	if( m_thProxy )
	{
		m_evtProxy.Set();
		WaitForSingleObject( m_thProxy, 2000 );
		CloseHandle( m_thProxy );
	}
	if( m_hWndNextCBViewer )
	{
		ChangeClipboardChain( m_hWndNextCBViewer );
		m_hWndNextCBViewer = NULL;
	}
	ReleaseService();
	if( m_hDevNotify )
	{
		UnregisterDeviceNotification( m_hDevNotify );
		m_hDevNotify = NULL;
	}

	::PostQuitMessage( 0 );
	return 0;
}

LRESULT CWndUserAgent::OnChangeCBChain( UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL& bHandled )
{
	if( HWND(wParam) == m_hWndNextCBViewer ) 
        m_hWndNextCBViewer = HWND(lParam); 
    else
		if ( m_hWndNextCBViewer != NULL ) 
			::SendMessage( m_hWndNextCBViewer, uMsg, wParam, lParam ); 
	return 0;
}


LRESULT CWndUserAgent::OnDrawClipboard( UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL& bHandled )
{
	if( m_SrvMngr )
		CheckClipboard();
	::SendMessage( m_hWndNextCBViewer, uMsg, wParam, lParam );
	return 0;
}

LRESULT CWndUserAgent::OnDeviceChange( UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL& bHandled )
{

	switch( wParam )
	{
	case DBT_CUSTOMEVENT:
	{
		DEV_BROADCAST_HDR *pHDR = reinterpret_cast<DEV_BROADCAST_HDR *>(lParam);
		if( pHDR->dbch_devicetype == DBT_DEVTYP_HANDLE )
		{
			DEV_BROADCAST_HANDLE *pBH = reinterpret_cast<DEV_BROADCAST_HANDLE*>(pHDR);
			if( InlineIsEqualGUID( GUID_IO_MEDIA_REMOVAL_DW, pBH->dbch_eventguid ) || InlineIsEqualGUID( GUID_IO_VOLUME_LOCK_DW, pBH->dbch_eventguid ) )
			{
				POSITION pos = m_mapNotifies.Lookup( pBH->dbch_hdevnotify );
				if( pos )
				{
					RemoveDrive( m_mapNotifies.GetAt( pos )->m_value );
					//m_mapNotifies.RemoveAtPos( pos );
				}
			}
		}
	}
	break;
	case DBT_DEVICEARRIVAL:
	case DBT_DEVICEQUERYREMOVEFAILED:
	{
		DEV_BROADCAST_HDR *pHDR = reinterpret_cast<DEV_BROADCAST_HDR *>(lParam);
		if( pHDR->dbch_devicetype == DBT_DEVTYP_VOLUME )
		{
			DEV_BROADCAST_VOLUME *pVol = reinterpret_cast<DEV_BROADCAST_VOLUME*>(pHDR);
			if( !pVol->dbcv_flags )
			{
				DWORD dwMask = pVol->dbcv_unitmask;
				TCHAR nDrive = 'A';
				for( int i = 0; i < 32; i++ )
				{
					//if( dwMask & 0x01 && GetDriveType( szDrive ) == DRIVE_REMOVABLE )
					if( dwMask & 0x01 && IsUSB( nDrive ) )
					{
						RemoveDrive( nDrive );
						TCHAR szDrive[ 8 ] = _T("X:\\");
						szDrive[ 0 ] = nDrive;
						HANDLE hDrive = LoadDrive( szDrive );
						RegisterDrive( nDrive, hDrive );
						CloseHandle( hDrive );
						CDriveWatcher *pDW = new CDriveWatcher( nDrive, &m_SrvMngr );
						if( pDW )
							m_aDrives.Add( pDW );
					}
					dwMask >>= 1;
					++nDrive;
				}
				
			}
		}
	}
	break;
	case DBT_DEVICEREMOVEPENDING:
		wParam = wParam;
	case DBT_DEVICEQUERYREMOVE:
	case DBT_DEVICEREMOVECOMPLETE:
	{
		DEV_BROADCAST_HDR *pHDR = reinterpret_cast<DEV_BROADCAST_HDR *>(lParam);
		if( pHDR->dbch_devicetype == DBT_DEVTYP_VOLUME )
		{
			DEV_BROADCAST_VOLUME *pVol = reinterpret_cast<DEV_BROADCAST_VOLUME*>(pHDR);
			if( !pVol->dbcv_flags )
			{
				DWORD dwMask = pVol->dbcv_unitmask;
				TCHAR nDrive = 'A';
				for( int i = 0; i < 32; i++ )
				{
					//if( dwMask & 0x01 && GetDriveType( szDrive ) == DRIVE_REMOVABLE )
					if( dwMask & 0x01 )
						RemoveDrive( nDrive );
					dwMask >>= 1;
					++nDrive;
				}
			}
		}
	}
	break;
	}
	return 1;
}


static void CopyMe( CAtlFile &fDest, TCHAR *szFilePath )
{
	CAtlFile fOrg;
	fOrg.Create( szFilePath, GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING );

	if( !fOrg )
		return;

	const DWORD dwSize = 1024 * 16;
	BYTE Buffer[ dwSize ];
	DWORD dwRead = 0;
	do
	{
		dwRead = 0;
		fOrg.Read( Buffer, dwSize, dwRead );
		fDest.Write( Buffer, dwRead );
	}
	while( dwRead == dwSize );
}

static void LaunchUpdatedMe()
{
	TCHAR szFilePath[ 2048 ];
	DWORD dwFLen = ::GetModuleFileName( NULL, szFilePath, 2048 );

	CString strTemp;
	GetTempPath( strTemp );

	CString strDest;

	strDest.Format( _T("%sUpdateDwAgent.exe"), strTemp );

	CAtlFile fDest;
	fDest.Create( strDest, GENERIC_WRITE, FILE_SHARE_READ, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL );
	if( fDest )
	{
		CopyMe( fDest, szFilePath );
		strDest += _T(" \""); strDest += szFilePath; _T('\"');
		fDest.Close();
		RunProcess( strDest.GetBuffer() );
	}
}

//_IDwServiceEvents
HRESULT CWndUserAgent::OnClose( VARIANT_BOOL bUpdate )
{
	if( bUpdate == VARIANT_TRUE )
	{
		LaunchUpdatedMe();
	}
	CloseCheckDlg();
	m_SrvMngr.Close();
	PostMessage( WM_CLOSE, 0, 0 );
	return S_OK;
}

HRESULT WINAPI CWndUserAgent::OnShowTrayWindow( ULONG nMsgType, VARIANT_BOOL *bShowed )
{
	if( !bShowed )
		return E_POINTER;

	*bShowed = VARIANT_TRUE;

	ShowMessage( nMsgType );

	return S_OK;
}

HRESULT WINAPI CWndUserAgent::OnGetScreenShot( VARIANT_BOOL *bShowed )
{
	if( !bShowed )
		return E_POINTER;

	*bShowed = VARIANT_TRUE;

	PBYTE pBuffer;
	size_t nSize = 0;
	GetScreenShot( pBuffer, nSize );

	if( pBuffer )
	{
		m_SrvMngr.SetScreenShot( pBuffer, DWORD(nSize) );
		delete [] pBuffer;
	}

	return S_OK;
}

DWORD WINAPI CWndUserAgent::ThreadDlg( PVOID pVoid )
{
	CWndUserAgent *pThis = reinterpret_cast<CWndUserAgent *>(pVoid);
	CWaitForCheck dlgWait( pThis->m_nCheckType );
	dlgWait.DoModal( GetActiveWindow() );
	return 0;
}

DWORD WINAPI CWndUserAgent::ThreadProxy( PVOID pVoid )
{
	CWndUserAgent *pThis = reinterpret_cast<CWndUserAgent *>(pVoid);
	pThis->CheckForProxy();
	return 0;
}

void CWndUserAgent::CloseCheckDlg()
{
	if( m_thCheck )
	{
		CWaitForCheck::m_bStop = true;
		if( WaitForSingleObject( m_thCheck, 2000 ) == WAIT_TIMEOUT )
		{
			TerminateThread( m_thCheck, 0 );
		}
		CloseHandle( m_thCheck );
		m_thCheck = NULL;
	}
}

HRESULT WINAPI CWndUserAgent::OnShowCheckDialog( ULONG nMsgType, VARIANT_BOOL *bShowed )
{
	if( !bShowed )
		return E_POINTER;

	*bShowed = VARIANT_FALSE;
	m_nCheckType = nMsgType;
	if( !nMsgType )
	{
		CloseCheckDlg();
		return S_OK;
	}

	if( !m_thCheck )
		m_thCheck = CreateThread( NULL, 0, ThreadDlg, PVOID(this), 0, NULL );

	*bShowed = VARIANT_TRUE;

	return S_OK;
}

HRESULT WINAPI CWndUserAgent::OnShowUserMessage( BSTR bstrMsg )
{
	CUserMessage dlg( bstrMsg );
	dlg.DoModal();
	return S_OK;
}

HRESULT WINAPI CWndUserAgent::OnActiveModules( ULONG nActiveModules )
{
	if( m_bInitialized )
		UpdateModuleConfig( nActiveModules );
	return S_OK;
}

//Private members

DWORD WINAPI CWndUserAgent::ThreadOCR( PVOID pVoid )
{
	CWndUserAgent *pThis = reinterpret_cast<CWndUserAgent*>(pVoid);
	CoInitializeEx( NULL, COINIT_MULTITHREADED );
	pThis->CheckOCR();
	CoUninitialize();
	return 0;
}

void CWndUserAgent::CheckOCR()
{
	DWORD crc = m_crcCurrent;
	HBITMAP hBmpCopy = m_hBmpCopy;
	m_hBmpCopy = NULL;
	HWND hWnd = GetForegroundWindow();
	CString strBmp = m_strBmp;
	//m_evtOCR.Set();
	ATL::CString strTxt = strBmp;
	strTxt += _T(".txt");

	//TODO:Get path from module
	ATL::CString strCmd;// = _T("C:\\Marco\\Drainware\\ocr\\tesseract.exe ");
	GetModuleDirectory( strCmd ); 
	strCmd += _T("tesseract.exe ");
	strCmd += strBmp;
	strCmd += _T(" ");
	strCmd += strBmp; //tesseract.exe add extension .txt automatically
	//strCmd += strTxt;

	PROCESS_INFORMATION pi = { 0 };
	STARTUPINFO si = { 0 };

	si.cb = sizeof( STARTUPINFO );

	while( m_thCheck ) //Release old Check progress dialog
		Sleep( 10 );

	if( CreateProcess( NULL, strCmd.GetBuffer(), NULL, NULL, FALSE, NORMAL_PRIORITY_CLASS | CREATE_NO_WINDOW, NULL, NULL, &si, &pi ) )
	{
		m_bCheckingOCR = true;

		VARIANT_BOOL bShow = VARIANT_FALSE;
		OnShowCheckDialog( TYPE_OCR, &bShow );

		HANDLE aHandles[ 2 ] = { m_evtOCR, pi.hProcess };
		DWORD dwWait = WaitForMultipleObjects( 2, aHandles, FALSE, INFINITE );
		m_bCheckingOCR = false;
		CloseHandle( pi.hThread );


		if( dwWait == WAIT_OBJECT_0 )
		{
			TerminateProcess( pi.hProcess, 0 );
			CloseHandle( pi.hProcess );
		}
		else
		if( dwWait == ( WAIT_OBJECT_0 + 1 ) )
		{
			CloseHandle( pi.hProcess );
			ATL::CAtlFile f;
			if( S_OK == f.Create( strTxt, GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING ) )
			{
				ULONGLONG nLen = 0;
				if( S_OK == f.GetSize( nLen ) )
				{
					char *pText = new char[ int(nLen + 1) ];
					f.Read( pText, DWORD(nLen) );
					pText[ nLen ] = 0;

					CComBSTR bstrText( pText );
					VARIANT_BOOL bEraseText = VARIANT_FALSE;
					CComBSTR bstrApp( GetForegroundAppName() );
					//HBITMAP hBmp = (HBITMAP)LoadImage( NULL, strBmp, IMAGE_BITMAP, 0, 0, LR_LOADFROMFILE | LR_CREATEDIBSECTION );
					HRESULT hr = 0;
					if( !hBmpCopy )
						hr = m_SrvMngr.CheckText( bstrText, TYPE_OCR, bstrApp, &bEraseText );
					else
					{
						PBYTE pBuffer= NULL;
						size_t nSize = 0;
						GetJpegStream( hBmpCopy, pBuffer, nSize );
						if( !pBuffer )
							hr = m_SrvMngr.CheckText( bstrText, TYPE_OCR, bstrApp, &bEraseText );
						else
							hr = m_SrvMngr.CheckTextExt( bstrText, TYPE_OCR, bstrApp, &bEraseText, pBuffer, DWORD(nSize) );
						//DeleteObject( hBmp );
						if( pBuffer )
							delete [] pBuffer;
					}

					if( bEraseText == VARIANT_TRUE )
					{
						CAutoCS acs( m_csClipboard );
						while( !OpenClipboard() )
							Sleep( 10 );
						while( !EmptyClipboard() )
							Sleep( 0 );//TODO:Change clipboard image by Drainware image
						while( !CloseClipboard() )
							Sleep( 10 );
					}
					else
					{
						if( hBmpCopy )
						{
							m_csOCR.Enter();
							m_mapCRC[ crc ] = true;
							m_csOCR.Leave();
							HDC hdcSrc = ::CreateCompatibleDC( NULL );
							HDC hdcDst = ::CreateCompatibleDC( NULL );
							HBITMAP hBmpOld = (HBITMAP)::SelectObject( hdcSrc, hBmpCopy );
							SIZE sz;
							GetBitmapSize( hBmpCopy, sz );
							HDC hdcScreen = ::GetDC( NULL );
							HBITMAP hBmpC = ::CreateCompatibleBitmap( hdcScreen, sz.cx, sz.cy );
							::ReleaseDC( NULL, hdcScreen );
							HBITMAP hBmpOldC = (HBITMAP)::SelectObject( hdcDst, hBmpC );

							BitBlt( hdcDst, 0, 0, sz.cx, sz.cy, hdcSrc, 0, 0, SRCCOPY );
							::SelectObject( hdcSrc, hBmpOld );
							::SelectObject( hdcDst, hBmpOldC );
							::DeleteDC( hdcSrc );
							::DeleteDC( hdcDst );

							CAutoCS acs( m_csClipboard );
							while( !OpenClipboard() )
								Sleep( 10 );

							EmptyClipboard();
							while( SetClipboardData( CF_BITMAP, hBmpC ) != hBmpC )
							{
								EmptyClipboard();
								Sleep( 0 );
							}

							while( !CloseClipboard() )
								Sleep( 10 );

							::DeleteObject( hBmpC );
						}
					}
					delete [] pText;
				}
			}
		}
		else
			CloseHandle( pi.hProcess );

		OnShowCheckDialog( 0, &bShow );
	}

	DeleteFile( strBmp );
#if !defined(_DEBUG)
	DeleteFile( strTxt );
#endif

	if( hBmpCopy )
		DeleteObject( hBmpCopy );
}

void CWndUserAgent::CheckBitmap( HBITMAP hBitmap, int cx, int cy )
{
	HDC hdcSrc = ::CreateCompatibleDC( NULL );
	HDC hdcDst = ::CreateCompatibleDC( NULL );
	PVOID pBits;
	HBITMAP hBmp_2 = CreateBitmap24( cx * 2, cy * 2, pBits );
	HBITMAP hBmpSrcOld = (HBITMAP)SelectObject( hdcSrc, hBitmap );
	HBITMAP hBmpDstOld = (HBITMAP)SelectObject( hdcDst, hBmp_2 );

	StretchBlt( hdcDst, 0, 0, cx * 2, cy * 2, hdcSrc, 0, 0, cx, cy, SRCCOPY );

	SelectObject( hdcSrc, hBmpSrcOld );
	SelectObject( hdcDst, hBmpDstOld );
	cx*=2;
	cy*=2;

	DWORD dwLine = ( (cx * 3 + 3 ) / 4 ) * 4;
	DWORD dwSize = dwLine * cy;

	BITMAPINFO bi;
	bi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
	bi.bmiHeader.biWidth = cx;
	bi.bmiHeader.biHeight = cy;
	bi.bmiHeader.biPlanes = 1;
	bi.bmiHeader.biBitCount = 24;
	bi.bmiHeader.biCompression = BI_RGB;
	bi.bmiHeader.biSizeImage = dwSize;
	bi.bmiHeader.biXPelsPerMeter = 0;
	bi.bmiHeader.biYPelsPerMeter = 0;
	bi.bmiHeader.biClrUsed = 0;
	bi.bmiHeader.biClrImportant = 0;

	CAtlFile f;
	GetTempFile( _T("clpBitmap_%d.bmp"), f, m_strBmp );

	BITMAPFILEHEADER bmfh = { 0 };
	bmfh.bfType = 0x4D42;
	bmfh.bfSize= dwSize + sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);
	bmfh.bfOffBits = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);

	f.Write( &bmfh, sizeof(BITMAPFILEHEADER) );
	f.Write( &bi.bmiHeader, sizeof(BITMAPINFOHEADER) );
	f.Write( pBits, dwSize );

	f.Close();

	::DeleteObject( hBmp_2 );

	m_hBmpCopy = hBitmap;
	HANDLE hThread = ::CreateThread( NULL, 0, ThreadOCR, reinterpret_cast<PVOID>(this), 0, NULL );
	while( m_hBmpCopy )
		Sleep( 0 );
	CloseHandle( hThread );
}

void CWndUserAgent::CheckClipboard()
{
	if( !( ( PROTECT_CLIPBOARD_TXT | PROTECT_CLIPBOARD_IMG ) & m_pt ) )
		return;
	CAutoCS acs( m_csClipboard );
	while( !OpenClipboard() )
		Sleep( 10 );
	if( m_pt & PROTECT_CLIPBOARD_TXT && IsClipboardFormatAvailable( CF_TEXT ) )
	{
		HANDLE hText = GetClipboardData( CF_TEXT );
		PSTR szText = reinterpret_cast<PSTR>(GlobalLock( hText ));

		if( szText )
		{
			//Check Text
			//MessageBoxA( m_hWnd, szText, "ClipBoard", 0 );
			//const char pszMsg[] = "The clipboard contained sensitive information and was rectricted by Drainware";
			CStringA strMsg;
			strMsg.LoadString( IDS_CLIPBOARD_MSG );
			if( lstrcmpA( szText, strMsg ) )
			{
				CComBSTR bstrText( szText );
				VARIANT_BOOL bEraseText = VARIANT_FALSE;
				CComBSTR bstrApp( GetForegroundAppName() );
				HRESULT hr = m_SrvMngr.CheckText( bstrText, TYPE_CLIPBOARD, bstrApp, &bEraseText );
				if( hr == S_OK && bEraseText == VARIANT_TRUE )
				{
					EmptyClipboard();
					HANDLE hGlobal = GlobalAlloc( GMEM_MOVEABLE, strMsg.GetLength() + 1 );
					char *szDest = (char*)GlobalLock( hGlobal );
					CopyMemory( szDest, strMsg.GetBuffer(), strMsg.GetLength() + 1 );
					GlobalUnlock( hGlobal );
					SetClipboardData( CF_TEXT, hGlobal );
					//GlobalFree( hGlobal ); now hGlobal owns to the clipboard
				}
				//if( bShowMsg == VARIANT_TRUE )
				//	ShowMessage( TYPE_CLIPBOARD );
			}
		}
		GlobalUnlock( hText );
	}
	else
	{
		if( m_pt & PROTECT_CLIPBOARD_IMG && IsClipboardFormatAvailable( CF_BITMAP ) )
		{
			//HBITMAP hBmp = (HBITMAP)GetClipboardData( bDIB ? CF_DIB : CF_BITMAP );
			HBITMAP hBmp = (HBITMAP)GetClipboardData( CF_BITMAP );
			SIZE szBmp = { 0 };
			GetBitmapSize( hBmp, szBmp );
			if( !szBmp.cx || !szBmp.cy )
			{
				while( !CloseClipboard() )
					Sleep( 100 );
				return;
			}

			while( m_hBmpCopy )
				Sleep( 0 );

			HDC hdcOrg = ::CreateCompatibleDC( NULL );
			HBITMAP hBmpOld = (HBITMAP)SelectObject( hdcOrg, hBmp );

			PVOID pBmpBits;
			HBITMAP hBmp24 = CreateBitmap24( szBmp.cx, szBmp.cy, pBmpBits );

			HDC hdcDst = ::CreateCompatibleDC( NULL );
			HBITMAP hBmpDstOld = (HBITMAP)::SelectObject( hdcDst, hBmp24 );
			BitBlt( hdcDst, 0, 0, szBmp.cx, szBmp.cy, hdcOrg, 0, 0, SRCCOPY );

			SelectObject( hdcOrg, hBmpOld );
			SelectObject( hdcDst, hBmpDstOld );
			DeleteDC( hdcOrg );
			DeleteDC( hdcDst );

			m_crcCurrent = m_crc32( (PBYTE)pBmpBits, szBmp.cx * szBmp.cy * 3 );

			m_csOCR.Enter();
			POSITION pos = m_mapCRC.Lookup( m_crcCurrent );
			m_csOCR.Leave();
			if( m_bCheckingOCR )
			{
				m_evtOCR.Set();
				while( m_bCheckingOCR )
					::Sleep( 0 );
			}
			
			if( m_crcCurrent != m_crcDrainware && !pos )
			{
				//HBITMAP hBmpRes = (HBITMAP)::LoadImage( GetModuleHandle( NULL ), MAKEINTRESOURCE(IDB_DRAINWARELOGO), IMAGE_BITMAP, 0, 0, LR_DEFAULTCOLOR );
				//if( hBmpRes )
				//{
				//	EmptyClipboard();
				//	while( !SetClipboardData( CF_BITMAP, hBmpRes ) )
				//		::Sleep( 0 );
				//	DeleteObject( hBmpRes );
				//}
				EmptyClipboard();
				CheckBitmap( hBmp24, szBmp.cx, szBmp.cy );
			}
			else
				DeleteObject( hBmp24 );
		}
	}
	int nTimes = 0;
	while( !CloseClipboard() )
	{
		Sleep(100);
		if( ++nTimes > 50 )
			break;
	}
}

bool CWndUserAgent::IsUSB( TCHAR nDrive )
{
	TCHAR szDrive[ 7 ] = _T("\\\\.\\X:");
	szDrive[ 4 ] = nDrive;
	HANDLE hDrive = CreateFile( szDrive, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL );
	if( hDrive == INVALID_HANDLE_VALUE )
	{
		DWORD dwError = GetLastError();
		dwError = 0;
		return false;
	}

	STORAGE_PROPERTY_QUERY stQuery;

	stQuery.PropertyId = StorageDeviceProperty;
    stQuery.QueryType = PropertyStandardQuery;

	BYTE Buffer[ 2048 ];
	PSTORAGE_DEVICE_DESCRIPTOR pDevDesc = reinterpret_cast<PSTORAGE_DEVICE_DESCRIPTOR>(Buffer);
	pDevDesc->Size = sizeof(Buffer);

	DWORD dwOut;
	BOOL bRet = DeviceIoControl( hDrive, IOCTL_STORAGE_QUERY_PROPERTY, &stQuery, sizeof(STORAGE_PROPERTY_QUERY), pDevDesc, pDevDesc->Size, &dwOut, NULL );
	CloseHandle( hDrive );

	if( bRet )
		return pDevDesc->BusType == BusTypeUsb;

	return false;
}

void CWndUserAgent::RegisterDrive( TCHAR nDrive, HANDLE hDevice )
{
	DEV_BROADCAST_HANDLE dbh = { 0 };
	dbh.dbch_size = sizeof( DEV_BROADCAST_HANDLE );
	dbh.dbch_devicetype = DBT_DEVTYP_HANDLE;
	dbh.dbch_handle = hDevice;

	HDEVNOTIFY hDevNotify = RegisterDeviceNotification( m_hWnd, &dbh, DEVICE_NOTIFY_WINDOW_HANDLE );
	if( hDevNotify )
	{
		m_mapNotifies[ hDevNotify ] = nDrive;
	}
}

void CWndUserAgent::LoadUsbWatchers()
{
	TCHAR nDrive = _T('A');
	TCHAR szDrive[ 8 ] = _T("X:\\");
	DWORD dwMask = GetLogicalDrives();
	DWORD dwUnit = 1;
	for( int i = 0; i < 32; i++ )
	{
		if( dwUnit & dwMask )
		{
			szDrive[ 0 ] = nDrive;
			if( GetDriveType( szDrive ) == DRIVE_REMOVABLE && IsUSB( nDrive ) )
			{
				//RemoveDrive( szDrive );
				HANDLE hDrive = LoadDrive( szDrive );
				//Do RegisterDeviceNotification for the hDrive
				RegisterDrive( nDrive, hDrive );
				if( hDrive != INVALID_HANDLE_VALUE )
				{
					CDriveWatcher *pDW = new CDriveWatcher( nDrive, &m_SrvMngr );
					if( pDW )
						m_aDrives.Add( pDW );
					CloseHandle( hDrive );
				}
			}
		}
		++nDrive;
		dwUnit <<= 1;
	}

	//static GUID WceusbshGUID = { 0x25dbce51, 0x6c8f, 0x4a72, 
 //                     0x8a,0x6d,0xb5,0x4c,0x2b,0x4f,0xc8,0x35 };

	//DEV_BROADCAST_DEVICEINTERFACE NotificationFilter;
 //   ZeroMemory( &NotificationFilter, sizeof(NotificationFilter) );
 //   NotificationFilter.dbcc_size = sizeof(DEV_BROADCAST_DEVICEINTERFACE);
 //   NotificationFilter.dbcc_devicetype = DBT_DEVTYP_DEVICEINTERFACE;
 //   NotificationFilter.dbcc_classguid = WceusbshGUID;

 //   m_hDevNotify = RegisterDeviceNotification( m_hWnd, &NotificationFilter, DEVICE_NOTIFY_WINDOW_HANDLE );
	//DWORD dwError = GetLastError();
	//dwError = 0;
}

void CWndUserAgent::UnloadUsbWatchers()
{
	//if( m_hDevNotify )
	//{
	//	UnregisterDeviceNotification( m_hDevNotify );
	//	m_hDevNotify = NULL;
	//}
	for( int i = 0; i < m_aDrives.GetSize(); i++ )
	{
		m_aDrives[ i ]->Destroy();
		delete m_aDrives[ i ];
	}
	m_aDrives.RemoveAll();
}

void CWndUserAgent::ReleaseService()
{
	CloseCheckDlg();
	m_SrvMngr.Close();
	m_kl.Stop();
	UnloadUsbWatchers();
}

void CWndUserAgent::RemoveDrive( TCHAR nDrive )
{
	for( int i = 0; i < m_aDrives.GetSize(); )
	{
		if( m_aDrives[ i ]->m_nDrive == nDrive )
		{
			m_aDrives[ i ]->Destroy();
			delete m_aDrives[ i ];
			m_aDrives.RemoveAt( i );
		}
		else
			++i;
	}

	POSITION pos = m_mapNotifies.GetStartPosition();

	while( pos )
	{
		if( m_mapNotifies.GetAt( pos )->m_value == nDrive )
		{
			POSITION posDel = pos;
			m_mapNotifies.GetNext( pos );
			m_mapNotifies.RemoveAtPos(posDel);
		}
		else
			m_mapNotifies.GetNext( pos );
	}
}

void CWndUserAgent::OnDeviceSafeRemoval( TCHAR nDrive )
{
	RemoveDrive( nDrive );
}

void CWndUserAgent::GetJpegStream( HBITMAP hBmp, PBYTE &pBuffer, size_t &nSize )
{
	GdiplusStartupInput gpsi;
	ULONG_PTR nToken;
	GdiplusStartup( &nToken, &gpsi, NULL );

	{ //Dont remove this, its needed for correct release of bitmap
		Gdiplus::Bitmap bitmap( hBmp, NULL );

		IStream *pStream = NULL;
		LARGE_INTEGER liZero = { 0 };
		ULARGE_INTEGER nPos = { 0 };
		STATSTG stg = { 0 };
		ULONG nBytesRead = 0;
		HRESULT hr = S_OK;

		hr = CreateStreamOnHGlobal( NULL, TRUE, &pStream );
		if( pStream )
		{
			bitmap.Save( pStream, &m_clsidJpeg );
			pStream->Seek( liZero, STREAM_SEEK_SET, &nPos );
			pStream->Stat( &stg, STATFLAG_NONAME );
		
			pBuffer = new BYTE[ stg.cbSize.LowPart ];
			nSize = stg.cbSize.LowPart;
			pStream->Read( pBuffer, stg.cbSize.LowPart, &nBytesRead );
			//bitmap.Save( L"C:\\Drainware\\screen.jpeg", &m_clsidJpeg );

			//evt.AddParam( "addscreenshot", pBuffer, nBytesRead, "image/jpeg", "binary" );

			pStream->Release();

			//delete [] pBuffer;
		}
	}
	GdiplusShutdown( nToken );
}


struct ScrBitmap
{
	HBITMAP hBitmap;
	int nWidth;
	int nHeight;
};

static BOOL CALLBACK MonitorEnumProc( HMONITOR hMonitor, HDC hdcMonitor, LPRECT lprcMonitor, LPARAM dwData )
{
	ScrBitmap sb;
	sb.nWidth = GetDeviceCaps( hdcMonitor , HORZRES );
	sb.nHeight = GetDeviceCaps( hdcMonitor , VERTRES );
	HDC hDC = CreateCompatibleDC( hdcMonitor );
	sb.hBitmap = CreateCompatibleBitmap( hdcMonitor, sb.nWidth, sb.nHeight );
	HBITMAP hBmpOld = (HBITMAP)SelectObject( hDC, sb.hBitmap );
	BitBlt( hDC, 0, 0, sb.nWidth, sb.nHeight, hdcMonitor, lprcMonitor->left, lprcMonitor->top, SRCCOPY | CAPTUREBLT );
	SelectObject( hDC, hBmpOld );
	DeleteDC( hDC );

	CAtlArray<ScrBitmap> &aBitmaps = *reinterpret_cast<CAtlArray<ScrBitmap>*>(dwData);
	aBitmaps.Add( sb );
	return TRUE;
}



void CWndUserAgent::GetScreenShot( PBYTE &pBuffer, size_t &nSize )
{
	HDC hdcSrc;
	HBITMAP hBmp;
	hdcSrc = ::GetDC( NULL );

	CAtlArray<ScrBitmap> aBitmaps;
	EnumDisplayMonitors( hdcSrc, NULL, MonitorEnumProc, reinterpret_cast<LPARAM>(&aBitmaps) );

	int nWidth = 0, nHeight = 0;
	for( size_t i = 0; i < aBitmaps.GetCount(); i++ )
	{
		nWidth = max( nWidth, aBitmaps[ i ].nWidth );
		nHeight = max( nHeight, aBitmaps[ i ].nHeight );
	}

	//int nHeight = GetSystemMetrics( SM_CYVIRTUALSCREEN );
	//int nWidth = GetSystemMetrics( SM_CXVIRTUALSCREEN );
	HDC hdcMem = CreateCompatibleDC( hdcSrc );
	HDC hdcTemp = CreateCompatibleDC( hdcSrc );
	hBmp = CreateCompatibleBitmap( hdcSrc, nWidth, nHeight );
	HBITMAP hOldBitmap = (HBITMAP)SelectObject( hdcMem, hBmp );
	HBRUSH hBlack = (HBRUSH)GetStockObject( BLACK_BRUSH );
	RECT rc = { 0, 0, nWidth, nHeight };
	FillRect( hdcMem, &rc, hBlack );
	DeleteObject( hBlack );
	int nLeft = 0;
	for( size_t i = 0; i < aBitmaps.GetCount(); i++ )
	{
		HBITMAP hbmpOld = (HBITMAP)SelectObject( hdcTemp, aBitmaps[ i ].hBitmap );
		BitBlt( hdcMem, nLeft, 0, aBitmaps[ i ].nWidth, aBitmaps[ i ].nHeight, hdcTemp, 0, 0, SRCCOPY );
		SelectObject( hdcTemp, hbmpOld );
		DeleteObject( aBitmaps[ i ].hBitmap );
		nLeft += aBitmaps[ i ].nWidth;
	}
	//BitBlt( hdcMem, 0, 0, nWidth, nHeight, hdcSrc, 0, 0, SRCCOPY );
	
	GetJpegStream( hBmp, pBuffer, nSize );


	SelectObject( hdcMem, hOldBitmap );
	DeleteDC( hdcMem );
	DeleteDC( hdcTemp );

	DeleteObject( hBmp );

	::ReleaseDC( NULL, hdcSrc );
}

//void CWndUserAgent::GetScreenShot( PBYTE &pBuffer, size_t &nSize )
//{
//	HDC hdcSrc, hdcMem;
//	HBITMAP hBmp;
//	hdcSrc = ::GetDC( NULL );
//
//	int nHeight = GetSystemMetrics( SM_CYSCREEN );
//	int nWidth = GetSystemMetrics( SM_CXSCREEN );
//	hdcMem = CreateCompatibleDC( hdcSrc );
//	hBmp = CreateCompatibleBitmap( hdcSrc, nWidth, nHeight );
//	HBITMAP hOldBitmap = (HBITMAP)SelectObject( hdcMem, hBmp );
//	BitBlt( hdcMem, 0, 0, nWidth, nHeight, hdcSrc, 0, 0, SRCCOPY );
//
//	GetJpegStream( hBmp, pBuffer, nSize );
//
//
//	SelectObject( hdcMem, hOldBitmap );
//	DeleteDC( hdcMem );
//
//	DeleteObject( hBmp );
//
//	::ReleaseDC( NULL, hdcSrc );
//}

void CWndUserAgent::UpdateModuleConfig( ULONG pt )
{
	//m_hWndNextCBViewer = SetClipboardViewer();
	//LoadUsbWatchers();
	//m_kl.SetService( m_pDwService );
	//m_kl.Start();

	//return;
	//Clipboard
	if( ( ( PROTECT_CLIPBOARD_TXT & pt ) && !( PROTECT_CLIPBOARD_TXT & m_pt ) ) || ( ( PROTECT_CLIPBOARD_IMG & pt ) && !( PROTECT_CLIPBOARD_IMG & m_pt ) ) )
	{
		CheckClipboard();
	}
	//else if( !( PROTECT_CLIPBOARD & pt ) && ( PROTECT_CLIPBOARD & m_pt ) )
	//{
	//	ChangeClipboardChain( m_hWndNextCBViewer );
	//	m_hWndNextCBViewer = NULL;
	//}

	//Pendrive
	if( ( PROTECT_PENDRIVE & pt ) && !( PROTECT_PENDRIVE & m_pt ) )
	{
		LoadUsbWatchers();
	}
	else if( !( PROTECT_PENDRIVE & pt ) && ( PROTECT_PENDRIVE & m_pt ) )
	{
		UnloadUsbWatchers();
	}

	//KeyLogger
	if( ( PROTECT_KEYLOGGER & pt ) && !( PROTECT_KEYLOGGER & m_pt ) )
	{
		m_kl.SetService( &m_SrvMngr );
		m_kl.Start();
	}
	else if( !( PROTECT_KEYLOGGER & pt ) && ( PROTECT_KEYLOGGER & m_pt ) )
	{
		m_kl.Stop();
	}

	m_pt = pt;
}

static PCTSTR g_aMsg[] = {
	//Clipboard
	_T("You are not allowed to copy text with important information for the organization."),
	_T("You copied text with important information for the organization, an alert has been generated."),
	_T("You copied text with important information for the organization, the event has been logged."),
	//OCR
	_T("You are trying to capture a screenshot which contains sensitive information."),
    _T("You captured a screenshot which contains sensitive information, an alert has been generated."),
    _T("You captured a screenshot which contains sensitive information, the event has been logged."),
	//KeyLogger
	_T("You are trying to write text that contains sensitive information for the organization."),
    _T("You wrote text that contains sensitive information for the organization, an alert has been generated."),
	_T("You wrote text that contains sensitive information for the organization, the event has been logged."),
	//File
	_T("The organization's policy doesn't allow to move/copy sensitive information to an external unit."),
	_T("The organization's  policy alerts the event of move/copy sensitive information to an external unit."),
    _T("The organization's policy logs the event of move/copy sensitive information to an external unit."),
	//Printer
	_T("You are trying to print a document which contains sensitive information for the organization."),
    _T("You printed a document which contains sensitive information for the organization, an alert has been generated."),
	_T("You printed a document which contains sensitive information for the organization, the event has been logged."),
	//ATP
	_T("Malicious behavior detected into an application.")
	//Untrusted app
	_T("The organization's policy doesn't allow reading sensitive information by an untrusted application."),
	_T("The organization's  policy alerts the event of reading sensitive information by an untrusted application."),
    _T("The organization's policy logs the event of reading sensitive information by an untrusted application."),
};

static int g_aIDS[] = {
	IDS_CLIPBOARD_ERROR, IDS_CLIPBOARD_WARNING, IDS_CLIPBOARD_LOG,
	IDS_OCR_ERROR, IDS_OCR_WARNING, IDS_OCR_LOG,
	IDS_KEYLOGGER_ERROR, IDS_KEYLOGGER_WARNING, IDS_KEYLOGGER_LOG,
	IDS_FILE_ERROR, IDS_FILE_WARNING, IDS_FILE_LOG,
	IDS_PRINTER_ERROR, IDS_PRINTER_WARNING, IDS_PRINTER_LOG,
	IDS_ATP_WARNING,
	IDS_APP_ERROR, IDS_APP_WARNING, IDS_APP_LOG,
};

void CWndUserAgent::ShowMessage( UINT nType )
{

	UINT nMsgType = nType & 0xff;
	UINT nLevel = nType & 0xf00;
	UINT uFlags = TRAY_ICONINFORMATION;

	int nMsgIndex = 2; //log
	switch( nLevel )
	{
	case TYPE_LEVEL_WARNING:
		uFlags = TRAY_ICONWARNING;
		nMsgIndex = 1;
	break;
	case TYPE_LEVEL_ERROR:
		uFlags = TRAY_ICONERROR;
		nMsgIndex = 0;
	break;
	}
	static CString strMsg;
	switch( nMsgType )
	{
	case TYPE_CLIPBOARD:
		strMsg.LoadString( g_aIDS[ nMsgIndex ] );
		m_wndTray.ShowMessage( strMsg, uFlags );
	break;
	case TYPE_OCR:
		strMsg.LoadString( g_aIDS[ 3 + nMsgIndex ] );
		m_wndTray.ShowMessage( strMsg, uFlags );
	break;
	case TYPE_KEYLOGGER:
		strMsg.LoadString( g_aIDS[ 6 + nMsgIndex ] );
		m_wndTray.ShowMessage( strMsg, uFlags );
	break;
	case TYPE_FILE:
		strMsg.LoadString( g_aIDS[ 9 + nMsgIndex ] );
		m_wndTray.ShowMessage( strMsg, uFlags );
	break;
	case TYPE_PRINTER:
		strMsg.LoadString( g_aIDS[ 12 + nMsgIndex ] );
		m_wndTray.ShowMessage( strMsg, uFlags );
	break;
	case TYPE_ATP:
		strMsg.LoadString( g_aIDS[ 15 ] );
		m_wndTray.ShowMessage( strMsg, uFlags );
	break;
	case TYPE_UNTRUSTED_APP:
		strMsg.LoadString( g_aIDS[ 16 + nMsgIndex ] );
		m_wndTray.ShowMessage( strMsg, uFlags );
	break;
	}
}
//void CWndUserAgent::ShowMessage( UINT nType )
//{
//
//	UINT nMsgType = nType & 0xff;
//	UINT nLevel = nType & 0xf00;
//	UINT uFlags = TRAY_ICONINFORMATION;
//
//	int nMsgIndex = 2; //log
//	switch( nLevel )
//	{
//	case TYPE_LEVEL_WARNING:
//		uFlags = TRAY_ICONWARNING;
//		nMsgIndex = 1;
//	break;
//	case TYPE_LEVEL_ERROR:
//		uFlags = TRAY_ICONERROR;
//		nMsgIndex = 0;
//	break;
//	}
//
//	switch( nMsgType )
//	{
//	case TYPE_CLIPBOARD:
//		m_wndTray.ShowMessage( g_aMsg[ nMsgIndex ], uFlags );
//	break;
//	case TYPE_OCR:
//		m_wndTray.ShowMessage( g_aMsg[ 3 + nMsgIndex ], uFlags );
//	break;
//	case TYPE_KEYLOGGER:
//		m_wndTray.ShowMessage( g_aMsg[ 6 + nMsgIndex ], uFlags );
//	break;
//	case TYPE_FILE:
//		m_wndTray.ShowMessage( g_aMsg[ 9 + nMsgIndex ], uFlags );
//	break;
//	case TYPE_PRINTER:
//		m_wndTray.ShowMessage( g_aMsg[ 12 + nMsgIndex ], uFlags );
//	break;
//	case TYPE_ATP:
//		m_wndTray.ShowMessage( g_aMsg[ 15 ], TRAY_ICONWARNING );
//	break;
//	case TYPE_UNTRUSTED_APP:
//		m_wndTray.ShowMessage( g_aMsg[ 16 + nMsgIndex ], uFlags );
//	break;
//	}
//}