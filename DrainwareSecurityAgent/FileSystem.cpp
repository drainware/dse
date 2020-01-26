#include "stdafx.h"
#include "FileFollower.h"
#include <DriverSpecs.h>
#include <TlHelp32.h>
__user_code
#include <FltUser.h>
#include <Psapi.h>
#include "IFileSystemDriver.h"

#pragma comment(lib, "FltLib.lib")
#pragma comment(lib, "Psapi.lib" )
#pragma comment(lib, "version.lib")

#define DRAINWARE_FILTER_PORT_NAME L"\\DrainwareFilterPort"
#define DRAINWARE_FILTER_NAME L"DrainwareFilter"

#pragma warning(push)
#pragma warning(disable:4200) // disable warnings for structures with zero length arrays.

struct DwRename
{
	ULONG nType;
	ULONG nPID;
	ULONG nSizeOld; //Size in bytes
	ULONG nSizeNew; //Size in bytes
	WCHAR szName[];

	ULONG DataSize() const throw()
	{
		return nSizeOld + nSizeNew + sizeof(ULONG) * 4;
	}

	PVOID DataPointer() throw()
	{
		return &nType;
	}

	WCHAR *OldName()
	{
		return szName;
	}

	WCHAR *NewName()
	{
		return szName + nSizeOld / sizeof(WCHAR);
	}
};

#pragma pack( 1 )

struct DwReadWrite
{
	ULONG nType;
	ULONG nPID;
	LONG nEvent;
	ULONG nSize; //Size in bytes or szName
	WCHAR szName[];

	ULONG DataSize() const throw()
	{
		return nSize + sizeof(ULONG) * 4;
	}

	PVOID DataPointer() throw()
	{
		return &nType;
	}

	WCHAR *Name()
	{
		return szName;
	}

};

struct DwReply
{
	FILTER_REPLY_HEADER frh;
	ULONG ulStatus;
};

struct DwCheckSvc
{
	LONG nEvent;
	ULONG nAction;
};

#pragma pack()

#pragma warning(pop)


struct CheckThread
{
	CString strFile;
	CString strUserName;
	CString strApp;
	CString strAppDesc;
	IFileSystemDriver *pFileSystemDriver;
	LONG nEvent;
	HANDLE hPort; 
	DWORD nPID;

	CheckThread( const CString &str, const CString &strUser, IFileSystemDriver *pFs,  LONG n, HANDLE h ) : strFile( str ), strUserName( strUser ), pFileSystemDriver( pFs ), nEvent( n ), hPort( h )
	{}
};


#define TYPE_RENAME 0
#define TYPE_READ 1
#define TYPE_WRITE 2

static ULONGLONG GetProcessAndUserNameOld( ULONG nPid, CString &strName, CString &strUserName )
{
	FILETIME ftCreation, ftExit, ftKernel, ftUser;
	strName.Empty();
	strUserName.Empty();
	HANDLE hProc = OpenProcess( PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, nPid );
	if( hProc )
	{
		GetProcessTimes( hProc, &ftCreation, &ftExit, &ftKernel, &ftUser );

		TCHAR szName[ 1024 ];
		DWORD dwSize = 1024;
		//QueryFullProcessImageName( hProc, 0, szName, &dwSize );
		GetProcessImageFileName( hProc, szName, 1024 );
		TCHAR *pProcName = StrRChr( szName, NULL, L'\\' );
		strName = pProcName ? pProcName + 1 : szName;
		HANDLE hToken;
		if( OpenProcessToken( hProc, TOKEN_QUERY, &hToken ) )
		{
			if( GetTokenInformation( hToken, TokenUser, szName, 1024, &dwSize ) )
			{
				PTOKEN_USER ptu = reinterpret_cast<PTOKEN_USER>(szName);
				dwSize = 1024;
				TCHAR szDomain[ 1024 ];
				DWORD dwSizeDomain = 1024;
				SID_NAME_USE snu;
				if( LookupAccountSid( NULL, ptu->User.Sid, szName, &dwSize, szDomain, &dwSizeDomain, &snu ) )
				{
					strUserName = szName;
				}
			}
			CloseHandle( hToken );
		}

		CloseHandle( hProc );
	}
	else
		ftCreation.dwHighDateTime = ftCreation.dwLowDateTime = 0;

	SYSTEMTIME st;
	FILETIME ftNow;
	GetSystemTime( &st );
	SystemTimeToFileTime( &st, &ftNow );

	ULARGE_INTEGER ul, ulNow;
	ul.HighPart = ftCreation.dwHighDateTime;
	ul.LowPart = ftCreation.dwLowDateTime;
	ulNow.HighPart = ftNow.dwHighDateTime;
	ulNow.LowPart = ftNow.dwLowDateTime;
	return ( ( ulNow.QuadPart - ul.QuadPart ) / 10000L ); //return milliseconds
}


struct ProcInfo
{
	CString strProcName;
	CString strOriginalName;
	CString strFileDesc;
	CString strUserName;
	bool bExist;
	bool bSystem;
	DWORD ProcIDParent;
};

volatile ULONG m_nCheckThreads = 0;
//CCriticalSection *m_pcsPID;
CCriticalSection m_csPID;
bool m_bReloadProcs;
bool g_bIsXP;

CAtlMap< ULONG, ProcInfo > m_mapPID2;

bool NormalizePath( CString &strRes );

static void GetOriginalFilename( TCHAR *szPath, CString &strName )
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
				WCHAR *szOriginalFilename = L"OriginalFilename";
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

static void GetProcessAndUserName( ULONG nPid, CString &strName, CString &strOriginalName, CString &strFileDesc, CString &strUserName )
{
	strName.Empty();
	strUserName.Empty();
	HANDLE hProc = OpenProcess( PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, nPid );
	if( hProc )
	{
		TCHAR szName[ 1024 ];
		DWORD dwSize = 1024;
		//QueryFullProcessImageName( hProc, 0, szName, &dwSize );
		GetProcessImageFileName( hProc, szName, 1024 );
		GetOriginalFilename( szName, strOriginalName );
		GetFileDescription( szName, strFileDesc );
		TCHAR *pProcName = StrRChr( szName, NULL, L'\\' );
		strName = pProcName ? pProcName + 1 : szName;
		HANDLE hToken;
		if( OpenProcessToken( hProc, TOKEN_QUERY, &hToken ) )
		{
			if( GetTokenInformation( hToken, TokenUser, szName, 1024, &dwSize ) )
			{
				PTOKEN_USER ptu = reinterpret_cast<PTOKEN_USER>(szName);
				dwSize = 1024;
				TCHAR szDomain[ 1024 ];
				DWORD dwSizeDomain = 1024;
				SID_NAME_USE snu;
				if( LookupAccountSid( NULL, ptu->User.Sid, szName, &dwSize, szDomain, &dwSizeDomain, &snu ) )
				{
					strUserName = szName;
				}
			}
			CloseHandle( hToken );
		}

		CloseHandle( hProc );
	}
}

TCHAR g_szInstanceName[ 256 ];

void StopFSDriver()
{
	SC_HANDLE hSCM = ::OpenSCManager( NULL, NULL, SC_MANAGER_ALL_ACCESS );
	if( hSCM )
	{
		SC_HANDLE hService = OpenService( hSCM, _T("DrainwareFilter"), SERVICE_ALL_ACCESS );
		if( hService )
		{
			SERVICE_STATUS ss;
			ControlService( hService, SERVICE_CONTROL_STOP, &ss );
			CloseServiceHandle( hService );
		}
		CloseServiceHandle( hSCM );
	}
	//FilterUnload( DRAINWARE_FILTER_NAME );
}

void StartFSDriver()
{
	SC_HANDLE hSCM = ::OpenSCManager( NULL, NULL, SC_MANAGER_ALL_ACCESS );
	if( hSCM )
	{
		SC_HANDLE hService = OpenService( hSCM, _T("DrainwareFilter"), SERVICE_ALL_ACCESS );
		if( hService )
		{
			StartService( hService, 0, NULL );
			CloseServiceHandle( hService );
		}
		CloseServiceHandle( hSCM );
	}
}

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

bool IsShortCut( LPCTSTR szPath )
{
	bool bRet = false;
	CoInitialize( NULL );
	CComPtr<IShellLink> pShellLink;
	HRESULT hr;
	if( S_OK == (hr = pShellLink.CoCreateInstance( CLSID_ShellLink ) ) )
	{
		CComPtr<IPersistFile> pPersist;
		pShellLink.QueryInterface( &pPersist );
		if( pPersist )
		{
			if( S_OK == pPersist->Load( szPath, STGM_READ ) )
			{
				if( S_OK == (hr = pShellLink->Resolve( NULL, SLR_NOLINKINFO | SLR_NO_UI | SLR_NOUPDATE | SLR_NOSEARCH | SLR_NOTRACK) ) )
					bRet = true;
			}
		}
	}
	CoUninitialize();
	return bRet;
}

//CCriticalSection m_csSend;
CCriticalSection m_csChecks;
CAtlArray< DwCheckSvc > m_aChecks;


bool IsXPOpenDlg()
{
	if( g_bIsXP )
	{
		HWND hWnd = GetForegroundWindow();
		if( hWnd )
		{
			TCHAR szName[ 128 ];
			if( GetClassName( hWnd, szName, 128 ) )
			{
				if( !lstrcmpi( szName, _T("#32770") ) )
				{
					//::OutputDebugStringA( "Is an open/save dialog\n" );
					return true;
				}
			}
		}
	}
	return false;
}

DWORD WINAPI ThreadCheckFile( PVOID pVoid )
{
	CheckThread *pCheck = reinterpret_cast<CheckThread *>(pVoid );
	CString strMsg;
	if( pCheck )
	{

		__declspec(align(64))  DwCheckSvc svc;
		svc.nAction = 2;
		svc.nEvent = pCheck->nEvent;
		{
			//strMsg = check.strFile;
			//strMsg.MakeLower();
			//if( strMsg.Find( _T(".lnk") ) == -1 )
			if( pCheck->strFile.Find( _T(".lnk") ) == -1 && !IsXPOpenDlg() )
			{
				strMsg.Format( _T("DwFilter: CheckFile: %s, UserName: %s, App: %s, PID: %d\n"), pCheck->strFile, pCheck->strUserName, pCheck->strApp, pCheck->nPID );
				::OutputDebugString( strMsg );

				//process_name:iexplorer.exe, description:'Internet Explorer', details:
				CString strJSON = _T("{\"process_name\":\""); strJSON += pCheck->strApp; 
				strJSON += _T("\", \"description\":\""); strJSON += pCheck->strAppDesc;
				strJSON += _T("\" }");

				if( pCheck->pFileSystemDriver->CheckFile( pCheck->strFile, pCheck->strUserName, strJSON ) )
					svc.nAction = 1; //Denied
			}
		}

		
		//{
		//	CAutoCS acs( m_csSend );
		//	DWORD dwDummy;
		//	FilterSendMessage( pCheck->hPort, &svc, sizeof( DwCheckSvc ), NULL, 0, &dwDummy );
		//}
		{
			CAutoCS acs(m_csChecks);
			m_aChecks.Add( svc );
		}
		strMsg.Format( _T("DwFilter: ThreadCheckFile File checked!!! Event: %d, Name: %s, User: %s\n"), pCheck->nEvent, pCheck->strFile, pCheck->strUserName );
		::OutputDebugString( strMsg );

		//FilterSendMessage makes FilterGetMessage to fail and return 0x80004005 (operation failed)
		delete pCheck;
	}
	//else
	//	::OutputDebugStringA( "DwFilter: ERROR !!!!!!!!!!!!!!!!!!!!!!!!!! not pCheck in ThreadCheckFile\n" );
	InterlockedDecrement( &m_nCheckThreads );
	return 0;
}

CString strWindows;
CString strProgramFiles_x86;
CString strProgramFiles;

struct FltInfo
{
	CString strDevice;
	CString strInstance;
};

CAtlArray<FltInfo> m_aInstances;

void LoadFilterInstancesOld()
{
	//Sleep( 20000 );
	TCHAR nDrive = _T('A');
	TCHAR szDrive[ 8 ] = _T("X:\\");
	DWORD dwMask = GetLogicalDrives();
	DWORD dwUnit = 1;


	for( int i = 0; i < 32; i++ )
	{
		if( dwUnit & dwMask )
		{
			szDrive[ 0 ] = nDrive;
			if( GetDriveType( szDrive ) == DRIVE_FIXED )
			{
				FltInfo &fi = m_aInstances[ m_aInstances.Add() ];
				fi.strDevice = szDrive;
				HRESULT hr = FilterAttach( DRAINWARE_FILTER_NAME, szDrive, NULL, MAX_PATH, fi.strInstance.GetBufferSetLength( MAX_PATH ) );
				hr = 0;
			}
		}
		++nDrive;
		dwUnit <<= 1;
	}

	{
	FltInfo &fi = m_aInstances[ m_aInstances.Add() ];
	fi.strDevice = _T("\\Device\\LanmanRedirector\\FLEXO\\Public");
	HRESULT hr = FilterAttach( DRAINWARE_FILTER_NAME, _T("\\Device\\LanmanRedirector"), NULL, MAX_PATH, fi.strInstance.GetBufferSetLength( MAX_PATH ) );
	hr = hr;
	}
	{
	FltInfo &fi = m_aInstances[ m_aInstances.Add() ];
	fi.strDevice = _T("\\Device\\Mup");
	HRESULT hr = FilterAttach( DRAINWARE_FILTER_NAME, _T("\\Device\\LanmanServer"), NULL, MAX_PATH, fi.strInstance.GetBufferSetLength( MAX_PATH ) );
	hr = hr;
	}
}

void LoadFilterInstances()
{
	DWORD dwSize = 1024;
	PBYTE pBuffer = new BYTE[ dwSize ];
	DWORD dwSizeOut = 0;
	HANDLE hFind = NULL;
	
	HRESULT hr = FilterVolumeFindFirst( FilterVolumeBasicInformation, pBuffer, dwSize, &dwSizeOut, &hFind );
	if( hr == HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER) )
	{
		delete [] pBuffer;
		dwSize = dwSizeOut + 128;
		hr = FilterVolumeFindFirst( FilterVolumeBasicInformation, pBuffer, dwSize, &dwSizeOut, &hFind );
	}

	if( hr == S_OK )
	{
		CString strVolName;
		CString strDbg;
		while( true )
		{
			PFILTER_VOLUME_BASIC_INFORMATION pVolume = reinterpret_cast<PFILTER_VOLUME_BASIC_INFORMATION>(pBuffer);
			strVolName.SetString( pVolume->FilterVolumeName, pVolume->FilterVolumeNameLength / 2 );
			FltInfo &fi = m_aInstances[ m_aInstances.Add() ];
			fi.strDevice = strVolName;
			//ERROR_FLT_INSTANCE_NAME_COLLISION
			hr = FilterAttach( DRAINWARE_FILTER_NAME, strVolName, NULL, MAX_PATH, fi.strInstance.GetBufferSetLength( MAX_PATH ) );
			//if( hr == S_OK )
			//	strDbg.Format( _T("DwInfo: Filter attached sucessfully to %s\n"), strVolName );
			//else
			//	strDbg.Format( _T("DwInfo: Filter failed attaching to %s, Error: 0x%08X\n"), strVolName, hr );
			//::OutputDebugString( strDbg );

			hr = FilterVolumeFindNext( hFind, FilterVolumeBasicInformation, pBuffer, dwSize, &dwSizeOut );
			if( hr == HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER) )
			{
				delete [] pBuffer;
				dwSize = dwSizeOut + 128;
				hr = FilterVolumeFindNext( hFind, FilterVolumeBasicInformation, pBuffer, dwSize, &dwSizeOut );
			}
			if( hr != S_OK )
				break;
		}
	}

	if( hFind )
		FilterVolumeFindClose( hFind );

	delete [] pBuffer;
}

void UnloadFilterInstances()
{
	for( size_t i = 0; i < m_aInstances.GetCount(); i++ )
		FilterDetach( DRAINWARE_FILTER_NAME, m_aInstances[ i ].strDevice, m_aInstances[ i ].strInstance );
	m_aInstances.RemoveAll();
}

void LoadDirectories()
{
	TCHAR szPath[ MAX_PATH ] = { 0 };
	GetWindowsDirectory( szPath, MAX_PATH );
	strWindows = szPath;
	strWindows.MakeUpper();

	if( S_OK == SHGetFolderPath( NULL, CSIDL_PROGRAM_FILES, NULL, SHGFP_TYPE_DEFAULT, szPath ) )
		strProgramFiles = szPath, strProgramFiles.MakeUpper();

	if( S_OK == SHGetFolderPath( NULL, CSIDL_PROGRAM_FILESX86, NULL, SHGFP_TYPE_DEFAULT, szPath ) )
		strProgramFiles_x86 = szPath, strProgramFiles_x86.MakeUpper();
}

bool IsSystemUser( CString &strUserName )
{
	if( strUserName == L"SYSTEM" || strUserName == L"LOCAL SERVICE" || strUserName == L"NETWORK SERVICE" )
		return true;
	return false;
}

bool MustCheck( CString &strCheck )
{
	if( strCheck.Find( strWindows ) != -1 )
		return false;

	if( strCheck.Find( strProgramFiles ) != -1 )
		return false;

	if( strProgramFiles_x86.GetLength() && strCheck.Find( strProgramFiles_x86 ) != -1 )
		return false;

	if( strCheck.Find( _T("APPDATA") ) != -1 )
		return false;

	if( strCheck.Find( _T("APPLICATION DATA") ) != -1 )
		return false;

	return true;
}

DWORD WINAPI ThreadLoadProcs( PVOID pVoid )
{
	IFileSystemDriver *pFileSystemDriver = reinterpret_cast<IFileSystemDriver *>(pVoid);

	CString strProc, strUserName, strOriginalName, strFileDesc, strMsg;
	const int nLimit = 25; //every 2,5 secs
	int n = nLimit;
	while( !pFileSystemDriver->Closed() && m_bReloadProcs )
	{
		if( n++ < nLimit )
		{
			Sleep( 100 );
			continue;
		}

		{
			CAtlMap< ULONG, ProcInfo > mapPID;

			{
				CAutoCS acs( m_csPID );
				POSITION pos = m_mapPID2.GetStartPosition();
				while( pos )
				{
					m_mapPID2.GetAt( pos )->m_value.bExist = false;
					mapPID[ m_mapPID2.GetKeyAt( pos ) ] = m_mapPID2.GetAt( pos )->m_value;
					m_mapPID2.GetNext( pos );
				}
			}

			//strMsg.Format( _T("DwFilter: Load process information\n"));
			//::OutputDebugString( strMsg );

			bool bUpdate = false;
			HANDLE hSnap = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );
			if( hSnap != INVALID_HANDLE_VALUE )
			{
				
				PROCESSENTRY32 pe32;
				pe32.dwSize = sizeof( PROCESSENTRY32 );


				if( Process32First( hSnap, &pe32 ) )
				{
					do
					{
						CAtlMap< ULONG, ProcInfo >::CPair *pPair = mapPID.Lookup( pe32.th32ProcessID );

						if( pPair )
							pPair->m_value.bExist = true;
						else
						{
							GetProcessAndUserName( pe32.th32ProcessID, strProc, strOriginalName, strFileDesc, strUserName );
							//if( !IsSystemUser( strUserName ) )
							{
								ProcInfo &pi = mapPID[ pe32.th32ProcessID ];
								pi.bExist = true;
								pi.strProcName = strProc;
								pi.strUserName = strUserName;
								pi.strOriginalName = strOriginalName;
								pi.strFileDesc = strFileDesc;
								pi.bSystem = IsSystemUser( strUserName );
								pi.ProcIDParent = pe32.th32ParentProcessID;
								bUpdate = true;
							}
						}
					}while( Process32Next( hSnap, &pe32 ) );
				}
				CloseHandle( hSnap );

				{
					CAutoCS acs( m_csPID );
					POSITION pos = mapPID.GetStartPosition();
					m_mapPID2.RemoveAll();
					while( pos )
					{
						if( mapPID.GetAt( pos )->m_value.bExist )
							m_mapPID2[ mapPID.GetKeyAt( pos ) ] = mapPID.GetAt( pos )->m_value;
						mapPID.GetNext( pos );
					}
				}
			}
			//strMsg.Format( _T("DwFilter: End Load process information\n"));
			//::OutputDebugString( strMsg );
		}

		n = 0;
	}
	return 0;
}

void SendChecks( HANDLE hPort )
{
	if( m_aChecks.GetCount() )
	{
		__declspec(align(64)) DwCheckSvc svc;
		CAtlArray<DwCheckSvc> aFailed;
		CAutoCS acs(m_csChecks);
		for( size_t i = 0; i < m_aChecks.GetCount(); i++ )
		{
			svc = m_aChecks[ i ];
			DWORD dwDummy;
			if( FilterSendMessage( hPort, &svc, sizeof( DwCheckSvc ), NULL, 0, &dwDummy ) != S_OK )
			{
				aFailed.Add( svc );
			}
			//else
			//{
			//	CString strDbg;
			//	strDbg.Format( _T("DwFilter: File Event: %d, %s\n"), svc.nEvent, svc.nAction == 1 ? _T("Access Denied!!!") : _T("Access Granted!!!") );
			//	::OutputDebugString( strDbg );
			//}
		}
		m_aChecks.RemoveAll();
		if( aFailed.GetCount() )
		{
			for( size_t i = 0; i< aFailed.GetCount(); i++ )
				m_aChecks.Add( aFailed[ i ] );
		}
	}

}

DWORD WINAPI ThreadFileSystem( PVOID pVoid )
{
	//Sleep( 20000 );
	//return 0;
	OSVERSIONINFO osvi = { 0 };
	osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
	GetVersionEx( &osvi );
	g_bIsXP = osvi.dwMajorVersion < 6;

	LoadDeviceNames();
	LoadDirectories();
	
	//m_pcsPID = &m_csPID;

	IFileSystemDriver *pFileSystemDriver = reinterpret_cast<IFileSystemDriver *>(pVoid);
	m_bReloadProcs = true;
	HANDLE hThreadLoadProcs = CreateThread( NULL, 0, ThreadLoadProcs, pVoid, 0, NULL );
	//return 0;
	//CAtlFile f;
	//f.Create( _T("C:\\drainware\\DwFilter.log"), GENERIC_WRITE, FILE_SHARE_READ, CREATE_ALWAYS );

	//Wake up DrainwareFilter

	StopFSDriver(); //Ensure that aren't other instances of the driver.

	StartFSDriver();
	//FilterLoad( DRAINWARE_FILTER_NAME );


	//LoadFilterInstances();
	CString strName, strNameCaps;
	CString strNameOld;
	CString strProc, strOriginalName;
	CString strUserName;
	CString strDbg;
	bool bShowMsg = true;

	//HANDLE hEvent = ::CreateEvent( NULL, FALSE, FALSE, NULL );
	//OVERLAPPED op = { 0 };
	//op.hEvent = hEvent;

	__declspec(align(64)) BYTE Buffer[ 4096 ];
	PFILTER_MESSAGE_HEADER pMsg = reinterpret_cast<PFILTER_MESSAGE_HEADER>(Buffer);

	__declspec(align(64)) DwReply dwR = { 0 };
	__declspec(align(64)) DwCheckSvc svc;

	DWORD nProcID = GetCurrentProcessId();

	while( true  )
	{
		if( pFileSystemDriver->Closed() )
			break;

		CHandle hPort;
		CHandle hCompletion;

		HRESULT hr = FilterConnectCommunicationPort( DRAINWARE_FILTER_PORT_NAME, 0, NULL, 0, NULL, &hPort.m_h );

		if( IS_ERROR( hr ) )
			break;

		hCompletion.Attach( CreateIoCompletionPort( hPort, NULL, 0, 0 ) );

		svc.nAction = 3;
		svc.nEvent = nProcID;
		DWORD dwDummy;
		FilterSendMessage( hPort, &svc, sizeof( DwCheckSvc ), NULL, 0, &dwDummy );

		while( true )
		{
			if( pFileSystemDriver->Closed() )
			{
				svc.nAction = 4;
				svc.nEvent = 0;
				FilterSendMessage( hPort, &svc, sizeof( DwCheckSvc ), NULL, 0, &dwDummy );
				break;
			}
			//if( hPort )
			//	hr = FilterGetMessage( hPort, pMsg, 4096, NULL/*&op*/ );

			OVERLAPPED ovlp = { 0 };

			hr = FilterGetMessage( hPort, pMsg, 4096, &ovlp );

			if( hr == HRESULT_FROM_WIN32( ERROR_IO_PENDING ) )
			{
				while( true )
				{
					DWORD dwOutSize;
					ULONG_PTR key;
					LPOVERLAPPED pOvlp;
					if( !GetQueuedCompletionStatus( hCompletion, &dwOutSize, &key, &pOvlp, 100 ) )
					{
						if( !pOvlp )//Is a timeout
						{
							if( m_aChecks.GetCount() )
								SendChecks( hPort );
						}
						else
							break;
					}
					else
						break;
				}
			}
			else
			if( hr != S_OK || !hPort)
			{
				if( pFileSystemDriver->Closed() )
					break;
				//strDbg.Format( _T("DwFilter: FilterGetMessage Error!!!!!!!!!!! 0x%08X\n"), hr );
				//::OutputDebugString( strDbg );
				if( hr == E_FAIL )
				{
					svc.nAction = 4;
					svc.nEvent = 0;
					FilterSendMessage( hPort, &svc, sizeof( DwCheckSvc ), NULL, 0, &dwDummy );
					//UnloadFilterInstances();
					//LoadFilterInstances();
					//strDbg.Format( _T("DwFilter: Trying to reload filter!!!!!!!!!!! \n") );
					//::OutputDebugString( strDbg );
					hPort.Close();
					hCompletion.Close();
					hr = FilterConnectCommunicationPort( DRAINWARE_FILTER_PORT_NAME, 0, NULL, 0, NULL, &hPort.m_h );
					if( IS_ERROR( hr ) )
						break;
					hCompletion.Attach( CreateIoCompletionPort( hPort, NULL, 0, 0 ) );
					svc.nAction = 3;
					svc.nEvent = nProcID;
					FilterSendMessage( hPort, &svc, sizeof( DwCheckSvc ), NULL, 0, &dwDummy );

				}
				continue;
				//FilterDetach( DRAINWARE_FILTER_NAME, (PWSTR)szDevice, g_szInstanceName );
				//StopFSDriver();
				//StartFSDriver();
				//if( S_OK != FilterAttach( DRAINWARE_FILTER_NAME, szDevice, NULL, sizeof( g_szInstanceName ), g_szInstanceName ) )
				//	break;
				//if( S_OK != FilterConnectCommunicationPort( DRAINWARE_FILTER_PORT_NAME, 0, NULL, 0, NULL, &hPort.m_h ) )
				//	break;
			}
			{
				DWORD dwRetFilter = 0;
				DwReadWrite *pReadWrite = reinterpret_cast<DwReadWrite *>( &Buffer[ sizeof(FILTER_MESSAGE_HEADER) ] );
				//ULONGLONG nProcTime = GetProcessAndUserName( pReadWrite->nPID, strProc, strUserName );
				if( pReadWrite->nPID != nProcID  )
				{
					CAutoCS acs( m_csPID );
					CAtlMap< ULONG, ProcInfo >::CPair *pPair = m_mapPID2.Lookup( pReadWrite->nPID );
					//strDbg.Format( _T("DwFilter: Get Process Pair: %s\n"), ( pPair ? _T("OK") : _T("Failed") ));
					//::OutputDebugString( strDbg );

					if( pPair /*&& !pPair->m_value.bSystem*/ && pPair->m_value.ProcIDParent != nProcID )
					{
						strProc = pPair->m_value.strProcName;
						strUserName = pPair->m_value.strUserName;
						strOriginalName = pPair->m_value.strOriginalName;
						strName.SetString( pReadWrite->Name(), pReadWrite->nSize / 2 );
						//if( pReadWrite->nPID != nProcID )
						{
							NormalizePath( strName );
							strNameCaps = strName;
							strNameCaps.MakeUpper();

							const DWORD dwMask = FILE_ATTRIBUTE_TEMPORARY | FILE_ATTRIBUTE_SPARSE_FILE | FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_SYSTEM;
							//const DWORD dwMask = FILE_ATTRIBUTE_TEMPORARY | FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_SYSTEM;
							//const DWORD dwMask = FILE_ATTRIBUTE_DIRECTORY;
							WIN32_FILE_ATTRIBUTE_DATA wfad = {0};
							//DWORD dwAtt = GetFileAttributes( strName );
							DWORD dwAtt = 0;
							if( GetFileAttributesEx( strName, GetFileExInfoStandard, &wfad ) )
							{
								if( wfad.nFileSizeLow || wfad.nFileSizeHigh )
									dwAtt = wfad.dwFileAttributes;
							}
							bool bCheck = true;
							if( strName[ 0 ] == _T('\\') && strName[ 0 ] == _T('\\') ) 
							{
								if( !pFileSystemDriver->IsRemoteFile( strName, strUserName ) )
									bCheck = false;
							}
							else if( IsSystemUser( strUserName ) )
								bCheck = false;

							if( !( ( dwMask ) & dwAtt ) && bCheck && MustCheck( strNameCaps ) )
							{
								//strDbg.Format( _T("DwFilter: Testing file: %s, Proc: %s, Event: %d\n"), strName, strProc, pReadWrite->nEvent );
								//::OutputDebugString( strDbg );
								if( /*!strProc.CompareNoCase( _T("notepad.exe") ) ||*/ pFileSystemDriver->OnCheckProc( strProc, strUserName ) 
									|| ( strOriginalName.GetLength() && strOriginalName != strProc && pFileSystemDriver->OnCheckProc( strOriginalName, strUserName )  )  )
								{
									CheckThread *pCheck = new CheckThread( strName, strUserName, pFileSystemDriver, pReadWrite->nEvent, hPort );
									pCheck->strApp = strProc; 
									pCheck->strAppDesc = pPair->m_value.strFileDesc;
									pCheck->nPID = pReadWrite->nPID;
									InterlockedIncrement( &m_nCheckThreads );
									HANDLE hThread = CreateThread( NULL, 0/*1024 * 64*/, ThreadCheckFile, reinterpret_cast<PVOID>(pCheck), 0, NULL );
									if( !hThread )
										::OutputDebugStringA( "DwFilter: Failed!!!!!! to Create Check Thread\n" );
									CloseHandle( hThread );
									dwRetFilter = 1;
								}
							
							}
							//else
							//{
							//	strDbg.Format( _T("DwFilter: Avoid of CheckFile of %s DUE TO ATTRIBUTES"), strName );
							//	::OutputDebugString( strDbg );
							//}
						}
					}
				}
				else
				{
					//strDbg.Format( _T("DwMsg: Omiting our PROC!!!: %d\n"), pReadWrite->nEvent ),
					//::OutputDebugString( strDbg );
				}
				dwR.frh.MessageId = pMsg->MessageId;
				dwR.frh.Status = 0;
				dwR.ulStatus = dwRetFilter;
				//if( dwRetFilter == 1 )
				//	strDbg.Format( _T("DwMsg: Before FilterReplyMessage: %d\n"), pReadWrite->nEvent ),
				//	::OutputDebugString( strDbg );
				{
					//CAutoCS acs( m_csSend );
					hr = FilterReplyMessage( hPort, (PFILTER_REPLY_HEADER)&dwR, sizeof( DwReply ) );
					if( hr != S_OK )
					{
						strDbg.Format( _T("DwFilter: FilterReplyMessage Failed, Error 0x%08X\n"), hr );
						::OutputDebugString( strDbg ) ;
						Sleep( 0 );
					}
				}

				SendChecks( hPort );
				//if( dwRetFilter == 1 )
				//	strDbg.Format( _T("DwMsg: After FilterReplyMessage: %d\n"), pReadWrite->nEvent ),
				//	::OutputDebugString( strDbg );
			}
		}
	}

	//::CloseHandle( hEvent );
	//hr = FilterDetach( DRAINWARE_FILTER_NAME, (PWSTR)szDevice, g_szInstanceName );
	::OutputDebugString( _T("DwFilter: Waiting Threads to end\n") );
	int nRetry = 0;
	while( m_nCheckThreads && ++nRetry < 100 * 10 ) //Wait a much for 10 seconds
		Sleep( 10 );

	m_bReloadProcs = false;
	CHandle hPort;
	FilterConnectCommunicationPort( DRAINWARE_FILTER_PORT_NAME, 0, NULL, 0, NULL, &hPort.m_h );
	if( hPort )
	{
		svc.nAction = 4;
		svc.nEvent = 0;
		DWORD dwDummy;
		::OutputDebugString( _T("DwFilter: Sending Message to Filter for end\n") );
		FilterSendMessage( hPort, &svc, sizeof( DwCheckSvc ), NULL, 0, &dwDummy );
	}

	//::OutputDebugString( _T("DwFilter: Unload filter instances\n") );
	//UnloadFilterInstances();

	::OutputDebugString( _T("DwFilter: Stopping filter\n") );
	StopFSDriver();
	WaitForSingleObject( hThreadLoadProcs, 1000 * 12 );
	CloseHandle( hThreadLoadProcs );
	::OutputDebugString( _T("DwFilter: Exit from FileSystem Thread\n") );
	return 0;
}
