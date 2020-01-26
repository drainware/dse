// DrainwareSecurityAgent.cpp: implementación de WinMain


#include "stdafx.h"
#include "resource.h"
#include "DrainwareSecurityAgent_i.h"
#include "IUserNotify.h"
#include "DDI.h"
#include "UserData.h"
#include "DwService.h"
#include "ISecurityAgent.h"
#include "FileFollower.h"

#include <stdio.h>
//#include <atlhttp.h>
#include <atldbcli.h>
#include "..\..\DrainwareLibs\json-c\json.h"
#include "../DwLib/DseVersion.h"
#include "IFileSystemDriver.h"
#include "Crypt.h"
#include <algorithm>

//CCrypt g_crypt;
//Register service: DrainwareSecurityAgent /Service
//UnRegister service: DrainwareSecurityAgent /UnregServer

#define DWM_NAME _T("Drainware Printer Monitor")

struct HeapLockApp
{
	CString m_strName;
	CAtlList< CString > m_lstExtension;
	DWORD m_dwNOPSledLengthMin;
	DWORD m_dwPrivateUsageMax;
	DWORD m_dwGenericPreAllocate;
	CStringA m_strSearchString;
	DWORD m_dwSearchMode;
	DWORD m_dwNullPagePreallocate;
	DWORD m_dwVerbose;
	DWORD m_dwutil_printf;
	DWORD m_dwForceTermination;
	DWORD m_dwResumeMonitoring;
};

struct RemoteFile
{
	CString strUser;
	CString strDestDir;
	CString strFileOrg;
	CString strRemoteUnit;
};

void GetWifiLocations( CStringA &strLocations, CAtlArray< CString > &aProxy, bool bProxyEnable );
DWORD WINAPI ThreadFileSystem( PVOID pVoid );
void StopFSDriver();

//static bool GetRegKey( LPCTSTR szKey, CRegKey &rKey )
//{
//	if( ERROR_SUCCESS != rKey.Open( HKEY_LOCAL_MACHINE, szKey, KEY_READ | KEY_WRITE ) )
//	{
//		if( ERROR_SUCCESS != rKey.Create( HKEY_LOCAL_MACHINE, szKey, NULL, 0, KEY_READ | KEY_WRITE ) )
//		{
//			DWORD dwErr = GetLastError();
//			return false;
//		}
//	}
//	return true;
//}


extern void InitPHP();
extern void ShutdownPHP();

//extern "C"
//{
//	void InitPHP();
//	void ShutdownPHP();
//}

class CDrainwareSecurityAgentModule : public ATL::CAtlServiceModuleT< CDrainwareSecurityAgentModule, IDS_SERVICENAME >,
	public ISecurityAgent,
	public IDDINotify,
	public IFileSystemDriver
{
public:

	typedef ATL::CAtlServiceModuleT< CDrainwareSecurityAgentModule, IDS_SERVICENAME > _Base;

	DECLARE_LIBID(LIBID_DrainwareSecurityAgentLib)
	DECLARE_REGISTRY_APPID_RESOURCEID(IDR_DRAINWARESECURITYAGENT, "{D8943E2A-4F83-49CE-B4DC-813B039976E1}")

	CDrainwareSecurityAgentModule() : m_dwLoadAppInit( 0 ), m_bPendingEvents( true ), m_hThreadPrinter( NULL ), 
		m_bClosing( false ), m_nDDIPort( 443 ), m_hThreadRemoteFiles( NULL ), m_hThreadDDI( NULL ), m_hThreadUpdate( NULL ), m_hThreadFS( NULL ), m_dwEnableFS( 1 ), 
		m_bOnShutdown( false ), m_bReloadPolicies( false ), m_bUpdate( VARIANT_FALSE ), m_bProxyEnable( 0 )
	{

		m_status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
	}

	HRESULT InitializeSecurity() throw()
	{
		// TODO: Llame a CoInitializeSecurity y proporcione la configuración de seguridad adecuada para el servicio.
		// Sugerencia: autenticación de nivel PKT, 
		// nivel de suplantación de RPC_C_IMP_LEVEL_IDENTIFY 
		// y un descriptor de seguridad no NULL apropiado.
		HRESULT hr = CoInitializeSecurity( NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_NONE, RPC_C_IMP_LEVEL_IDENTIFY, NULL, EOAC_NONE, NULL );
		UpdateSearchIndex();
		return S_OK;
	}

	BOOL Install() throw()
	{
		//This is called with administrator privileges from installer
		RegDLL( _T("DrainwareShellExt.dll") );
		RegDLL( _T("DrainwareSecurityAgentPS.dll") );

		if (IsInstalled())
			return TRUE;

		// Get the executable file path
		TCHAR szFilePath[MAX_PATH + _ATL_QUOTES_SPACE];
		DWORD dwFLen = ::GetModuleFileName(NULL, szFilePath + 1, MAX_PATH);
		if( dwFLen == 0 || dwFLen == MAX_PATH )
			return FALSE;

		// Quote the FilePath before calling CreateService
		szFilePath[0] = _T('\"');
		szFilePath[dwFLen + 1] = _T('\"');
		szFilePath[dwFLen + 2] = 0;

		SC_HANDLE hSCM = ::OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
		if (hSCM == NULL)
		{
			TCHAR szBuf[1024];
			if (AtlLoadString(ATL_SERVICE_MANAGER_OPEN_ERROR, szBuf, 1024) == 0)
#ifdef UNICODE
				Checked::wcscpy_s(szBuf, _countof(szBuf), _T("Could not open Service Manager"));
#else
				Checked::strcpy_s(szBuf, _countof(szBuf), _T("Could not open Service Manager"));
#endif
			MessageBox(NULL, szBuf, m_szServiceName, MB_OK);
			return FALSE;
		}

		DWORD dwServiceType = SERVICE_WIN32_OWN_PROCESS;// | SERVICE_INTERACTIVE_PROCESS;
		OSVERSIONINFO osvi = { 0 };
		osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
		GetVersionEx( &osvi );
		if( osvi.dwMajorVersion < 6 ) //XP
			dwServiceType |= SERVICE_INTERACTIVE_PROCESS;

		SC_HANDLE hService = ::CreateService(
			hSCM, m_szServiceName, m_szServiceName,
			SERVICE_ALL_ACCESS, dwServiceType,
			SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, //SERVICE_AUTO_START
			szFilePath, NULL, NULL, _T("RPCSS\0"), NULL, NULL);
			//szFilePath, NULL, NULL, _T("RPCSS\0SPOOLER\0LANMANSERVER\0"), NULL, NULL);

		if (hService == NULL)
		{
			::CloseServiceHandle(hSCM);
			TCHAR szBuf[1024];
			if (AtlLoadString(ATL_SERVICE_START_ERROR, szBuf, 1024) == 0)
#ifdef UNICODE
				Checked::wcscpy_s(szBuf, _countof(szBuf), _T("Could not start service"));
#else
				Checked::strcpy_s(szBuf, _countof(szBuf), _T("Could not start service"));
#endif
			MessageBox(NULL, szBuf, m_szServiceName, MB_OK);
			return FALSE;
		}

		SERVICE_FAILURE_ACTIONS sfa = { 0 };
		SC_ACTION acts[ 3 ] = { { SC_ACTION_RESTART, 1000 }, { SC_ACTION_RESTART, 1000 }, { SC_ACTION_RESTART, 1000 } };
		sfa.cActions = 3;
		sfa.lpsaActions = acts;
		ChangeServiceConfig2( hService, SERVICE_CONFIG_FAILURE_ACTIONS, &sfa );

		SERVICE_DESCRIPTION sd;
		sd.lpDescription = _T("Drainware Endpoint Service");
		ChangeServiceConfig2( hService, SERVICE_CONFIG_DESCRIPTION, &sd );

		::CloseServiceHandle(hService);
		::CloseServiceHandle(hSCM);

		//Save Proxy settings from current user

		CRegKey rKey;
		if( ERROR_SUCCESS == rKey.Open( HKEY_CURRENT_USER, _T("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"), KEY_READ | KEY_WOW64_32KEY ) )
		{
			TCHAR szValue[ MAX_PATH ] = { 0 };
			ULONG nSize = MAX_PATH;
			if( ERROR_SUCCESS == rKey.QueryStringValue( _T("ProxyServer"), szValue, &nSize ) )
			{
				DWORD nEnable = 0;
				rKey.QueryDWORDValue( _T("ProxyEnable"), nEnable );
				CRegKey rKeyConf;
				if( ERROR_SUCCESS == rKeyConf.Open( HKEY_LOCAL_MACHINE, _T("SOFTWARE\\Drainware\\SecurityEndpoint"), KEY_READ | KEY_WRITE ) )
				{
					rKeyConf.SetDWORDValue( _T("ProxyEnable"), nEnable );
					rKeyConf.SetStringValue( _T("ProxyServer"), szValue );
				}
			}
		}
		return TRUE;
	}

	HRESULT UnregisterServer( BOOL bUnRegTypeLib, const CLSID* pCLSID = NULL ) throw()
	{

		SC_HANDLE hSCM = ::OpenSCManager( NULL, NULL, SC_MANAGER_ALL_ACCESS );
		if( hSCM )
		{
			SC_HANDLE hService = OpenService( hSCM, m_szServiceName, SERVICE_ALL_ACCESS );
			if( hService )
			{
				SERVICE_STATUS ss;
				ControlService( hService, SERVICE_CONTROL_STOP, &ss );

				SERVICE_STATUS_PROCESS ssp;
				DWORD dwNeeded;
				int nRetries = 0;
				while( nRetries++ < 600 ) //try for 60 seconds
				{
					if( !QueryServiceStatusEx( hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(SERVICE_STATUS_PROCESS), &dwNeeded ) )
						break;
					if( ssp.dwCurrentState == SERVICE_STOPPED )
						break;
					Sleep( 100 );
				}
				CloseServiceHandle( hService );
			}
			CloseServiceHandle( hSCM );
		}

		RegDLL( _T("DrainwareShellExt.dll"), false );
		RegDLL( _T("DrainwareSecurityAgentPS.dll"), false );
		UninstallPrinterMonitor();

		return _Base::UnregisterServer( bUnRegTypeLib, pCLSID );
	}

	inline HRESULT RegisterAppId(_In_ bool bService = false) throw()
	{
		if (!Uninstall())
			return E_FAIL;

		HRESULT hr = UpdateRegistryAppId(TRUE);
		if (FAILED(hr))
			return hr;

		CRegKey keyAppID;
		LONG lRes = keyAppID.Open(HKEY_CLASSES_ROOT, _T("AppID"), KEY_WRITE);
		if (lRes != ERROR_SUCCESS)
			return AtlHresultFromWin32(lRes);

		CRegKey key;

		lRes = key.Create(keyAppID, GetAppIdT());
		if (lRes != ERROR_SUCCESS)
			return AtlHresultFromWin32(lRes);

		key.DeleteValue(_T("LocalService"));

		if (!bService)
			return S_OK;

		key.SetStringValue(_T("LocalService"), m_szServiceName);

		// Create service
		if (!Install())
			return E_FAIL;
		return S_OK;
	}

	HRESULT Run(_In_ int nShowCmd = SW_HIDE)
	{
		//Sleep( 20000 );

		//InitCrypt();
		LoadConfig();

		char szComputerName[ MAX_PATH ] = { 0 };
		DWORD dwSize = MAX_PATH;
		GetComputerNameA( szComputerName, &dwSize );
		m_strMachine = szComputerName;
		m_strIP = "127.0.0.1";

		GetModuleDirectory( m_strOfflineEvents );
		m_strOfflineEvents += _T("OfflineEvents.evt");
		m_ddi.SetDDINotify( this );
		m_evtUpdate.Create( NULL, FALSE, FALSE, NULL );
		m_evtPrintMonitor.Create( NULL, FALSE, FALSE, _T("DrainwarePrintMonitorEvt") );
		m_hThreadUpdate = CreateThread( NULL, 0, ThreadUpdate, reinterpret_cast<PVOID>(this), 0, NULL );
		m_hThreadDDI = CreateThread( NULL, 0, ThreadDDI, reinterpret_cast<PVOID>(this), 0, NULL );
		HANDLE hThreadGEO = CreateThread( NULL, 0, ThreadGeo, reinterpret_cast<PVOID>(this), 0, NULL );
		CloseHandle( hThreadGEO );

		if( m_dwEnableFS )
		{
			RegDriver();
			Sleep( 1000 );
			m_hThreadFS = CreateThread( NULL, 0, ThreadFileSystem, static_cast<IFileSystemDriver *>(this), 0, NULL );
			SetThreadPriority( m_hThreadFS, THREAD_PRIORITY_TIME_CRITICAL );
		}

		//RegShell();
#ifdef _DEBUG
		//RegATP();
#endif
		RegATP();
		RegDLL( _T("DrainwareShellExt.dll") );
		RegDLL( _T("DrainwareSecurityAgentPS.dll") );
		UninstallPrinterMonitor(); //Restore correct ports before new user be initialized

		CString strModuleDir;
		GetModuleDirectory( strModuleDir );
		SetCurrentDirectory( strModuleDir );

		InitPHP();
		HRESULT hRet = _Base::Run( nShowCmd );

		if( !m_bOnShutdown )
			ShutdownDW();

		return hRet;
	}



	void ShutdownDW() throw()
	{

		m_bClosing = true;
		m_evtPrintMonitor.Set();

		//m_fileFollower.Stop();
		CloseClients();
		//StopPrinter();
#ifdef _DEBUG
		//UnregATP();
#endif
		UnregATP();
		m_ddi.Stop( true );
		WaitForSingleObject( m_hThreadDDI, 15000 );
		CloseHandle( m_hThreadDDI );
		m_evtUpdate.Set();
		WaitForSingleObject( m_hThreadUpdate, 15000 );
		CloseHandle( m_hThreadUpdate );

		////Stop MiniFilter
		//CString strFile;
		//GetModuleDirectory( strFile );
		//strFile += "StopFilter.txt";
		//CAtlFile f;

		//f.Create( strFile, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, CREATE_ALWAYS );
		//
		//f.Close();
		//DeleteFile( strFile );

		if( m_hThreadFS )
		{
			if( WaitForSingleObject( m_hThreadFS, 2000 ) == WAIT_TIMEOUT )
			{
				StopFSDriver();
				WaitForSingleObject( m_hThreadFS, 2000 );
			}
			CloseHandle( m_hThreadFS );
			UnRegDriver();
		}

		WaitForSingleObject( m_hThreadRemoteFiles, INFINITE );
		UninstallPrinterMonitor();
		ShutdownPHP();
	}

	void OnShutdown() throw()
	{
		m_bOnShutdown = true;
		ShutdownDW();
	}

	//void OnStop() throw()
	//{

	//	DWORD dwState = SERVICE_STOP_PENDING;
	//	::InterlockedExchange( &m_status.dwCurrentState, dwState );
	//	m_status.dwWaitHint = 60000;
	//	::SetServiceStatus( m_hServiceStatus, &m_status );

	//	m_bOnShutdown = true;
	//	ShutdownDW();
	//	::InterlockedIncrement( &m_status.dwCheckPoint );
	//	::SetServiceStatus( m_hServiceStatus, &m_status );
	//	::PostThreadMessage(m_dwThreadID, WM_QUIT, 0, 0);
	//}

	//Interface IFileSystemDriver
	void OnFileRename( CString &strOld, CString &strName, CString &strProc, CString &strUser )
	{
		//m_fileFollower.Rename( strOld, strName );
	}

	//bool OnFileRead( CString &strName, CString &strProc, CString &strUser )
	//{
	//	CUserData *pUserData = GetUser( strUser, false );
	//	bool bRet = false;
	//	//if( pUserData && pUserData->IsMimeTypeOfProc( strProc, strName ) )
	//	if( pUserData && ( /*( strProc == _T("firefox.exe") && strName.Find( _T(".txt") ) != -1 ) ||*/ pUserData->IsMimeTypeOfProc( strProc, strName ) ) )
	//	{
	//		CStringA strEvent;
	//		//VARIANT_BOOL bShowMsg = VARIANT_FALSE;
	//		VARIANT_BOOL bDeleteFile = VARIANT_FALSE;
	//		bool bScreenShot = false;
	//		bool bSendEvent = false;
	//		pUserData->ClearScreenShot();
	//		if( pUserData->CheckFile( strName, strEvent, bDeleteFile, bScreenShot ) )
	//		{
	//			if( bScreenShot )
	//				Fire_ScreenShot( strUser );
	//			bSendEvent = true;
	//			if( bDeleteFile == VARIANT_TRUE )
	//				bRet = true;
	//		}

	//		if( bSendEvent )
	//			Fire_ShowMsg( strUser, TYPE_FILE | pUserData->ActionLevel() );

	//		if( bSendEvent )
	//		{
	//			pUserData->LockScreenShot();
	//			SendEvent( CStringA(strUser), strEvent, pUserData->GetScreenShot() );
	//			pUserData->UnlockScreenShot();
	//		}

	//	}
	//	return bRet;
	//}

	//void OnFileWrite( CString &strName, CString &strProc, CString &strUser )
	//{
	//}

	bool OnCheckProc( CString &strProc, CString &strUserName )
	{
		CUserData *pUserData = GetUser( strUserName, false );

		if( pUserData )
			return pUserData->FindApp( strProc );

		return false;
	}

	//bool CheckADR( CUserData *pUserData, CString &strFileOrg, CStringA &strEvent )
	//{
	//	CAtlFile f;
	//	CString strFileOrg = strFileOrg;
	//	strFileOrg += _T(":dwr.dat");

	//	if( S_OK == f.Create( strFileOrg, GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING ) )
	//	{
	//		CStringA strContent;
	//		ULONGLONG nSize = 0;
	//		if( S_OK == f.GetSize( nSize ) && nSize && S_OK == f.Read( strContent.GetBufferSetLength( int(nSize) ), DWORD(nSize) ) )
	//		{
	//			if( UncompressXOR( strContent ) )
	//			{
	//				DWORD nPos = 0;
	//				if( nPos + sizeof( DWORD ) <= DWORD(strContent.GetLength()) )
	//				{
	//					DWORD nFileOrgSize;
	//					CopyMemory( &nFileOrgSize, strContent.GetBuffer() + nPos, sizeof( DWORD ) );
	//					nPos += sizeof( DWORD );
	//					if( nPos + nFileOrgSize <= DWORD(strContent.GetLength()) )
	//					{
	//						CopyMemory( strFileOrg.GetBufferSetLength( nFileOrgSize / sizeof(TCHAR) ), strContent.GetBuffer() + nPos, nFileOrgSize );
	//						HRESULT hr = CheckRemoteUnit( strFileOrg.GetBuffer(), bstrFileDest, bDestIsExternFolder, bDeleteFile );
	//						pUserData->CheckRemoteUnit( strfileOrg,  strEvent, 
	//						if( *bDeleteFile == VARIANT_TRUE )
	//							return hr;
	//					}
	//				}
	//			}
	//		}
	//	}
	//}

	bool CheckFile( CString &strName, CString &strUser, CString &strApp )
	{
		CString strDbg;
		strDbg.Format( _T("DwFilter: Checking File: %s, User:%s\n"), strName, strUser );
		::OutputDebugString( strDbg );
		CUserData *pUserData = GetUser( strUser, false );
		bool bRet = false;
		if( pUserData )
		{
			CStringA strEvent;
			//VARIANT_BOOL bShowMsg = VARIANT_FALSE;
			VARIANT_BOOL bDeleteFile = VARIANT_FALSE;
			bool bScreenShot = false;
			bool bSendEvent = false;
			pUserData->ClearScreenShot();
			CString strRemote;

			if( ( strName[ 0 ] == _T('\\') && strName[ 1 ] == _T('\\') ) )
				strRemote = strName; //Is remote file
			else
				pUserData->GetRemoteFileName( strName, strRemote ); //is from network_place?

			CStringA strAppA;
			strAppA = strApp;
			if( strRemote.GetLength() )
			{
				if( pUserData->CheckRemoteUnit( strRemote, strEvent, bDeleteFile, bScreenShot, strAppA ) )
				{
					if( bScreenShot )
						Fire_ScreenShot( strUser );
					if( bDeleteFile == VARIANT_TRUE )
						bRet = true;
					Fire_ShowMsg( strUser, TYPE_UNTRUSTED_APP | pUserData->ActionLevel() );
					pUserData->LockScreenShot();
					SendEvent( CStringA(strUser), strEvent, pUserData->GetScreenShot() );
					pUserData->UnlockScreenShot();
				}
			}
			if( !bRet && pUserData->CheckFile( TYPE_APPLICATION_FILTER, strName, strEvent, bDeleteFile, bScreenShot, strAppA ) ) //If not blocked by remotefile check
			{
				strDbg.Format( _T("DwFilter: WARNING: File: \n%s\nDelete: %s\nScreenShot: %s\n"), strName, ( bDeleteFile == VARIANT_TRUE ? _T("true") : _T("false") ), ( bScreenShot ? _T("true") : _T("false") ) );
				::OutputDebugString( strDbg );
				if( bScreenShot )
					Fire_ScreenShot( strUser );
				if( bDeleteFile == VARIANT_TRUE )
					bRet = true;

				Fire_ShowMsg( strUser, TYPE_UNTRUSTED_APP | pUserData->ActionLevel() );
				pUserData->LockScreenShot();
				SendEvent( CStringA(strUser), strEvent, pUserData->GetScreenShot() );
				pUserData->UnlockScreenShot();
			}
			else
			{
				strDbg.Format( _T("DwFilter: File clean!!!\n") );
				::OutputDebugString( strDbg );
			}
		}
		else
		{
			strDbg.Format( _T("DwFilter: Not user Found!!!: %s"), strUser );
			::OutputDebugString( strDbg );
		}
		return bRet;
	}

	bool Closed()
	{
		return m_bClosing;
	}

	bool IsRemoteFile( const CString &strName, CString &strUser )
	{
		CUserData *pUserData = GetUser( strUser, false );
		if( pUserData )
		{
			CString strRemoteUnit;
			return pUserData->IsRemoteUnit( strName, strRemoteUnit );
		}
		return false;
	}


	//Interface ISecurityAgent
	CUserData *AddClient( CDwService *pClient )
	{
		CAutoCS acs( m_csClients );
		m_aClients.Add( pClient );
		CUserData *pUserData = GetUser( pClient->m_strUserName );
		pUserData->SetToken( pClient->m_token );
		return pUserData;
	}

	void AddIfRemoteFile( const CString &strUserName, const WCHAR *szDestDir, const WCHAR *szFileOrg, const WCHAR *szRemoteUnit )
	{
		if( szDestDir && szFileOrg )
		{
			CAutoCS acs(m_csRemoteFiles);
			RemoteFile &rf = m_aRemoteFiles[ m_aRemoteFiles.Add() ];
			rf.strUser = strUserName;
			rf.strDestDir = szDestDir;
			rf.strFileOrg = szFileOrg;
			rf.strRemoteUnit = szRemoteUnit;
		}
		else //ShellExt ended to send files to us
		{
			if( !m_hThreadRemoteFiles )
				m_hThreadRemoteFiles = CreateThread( NULL, 0, ThreadRemoteFiles, reinterpret_cast<PVOID>(this), 0, NULL );
		}
	}

	void RemoveADS( const WCHAR *szFileOrg ) //execept ads of remote units
	{
		if( IsDirectory( szFileOrg ) )
		{
			CString strFile = szFileOrg;
			strFile += _T('\\');
			CString strFind = strFile;
			strFind += _T('*');
			WIN32_FIND_DATA fd = { 0 };
			HANDLE hFind = FindFirstFile( strFind, &fd );

			if( hFind != INVALID_HANDLE_VALUE )
			{
				CString strFileChild;
				do
				{
					strFileChild = strFile;
					if( lstrcmp( fd.cFileName, _T(".") ) && lstrcmp( fd.cFileName, _T("..") ) )
					{
						strFileChild += fd.cFileName;
						RemoveADS( strFileChild );
					}
				}while( FindNextFile( hFind, &fd ) );
				FindClose( hFind );
			}
		}
		else
		{
			CAtlFile f;
			f.Create( szFileOrg, GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS );
			if( f )
			{
				VOID *ctx = NULL;
				BYTE Buffer[ 4096 ];
				WCHAR *pFileName = reinterpret_cast<WCHAR*>(Buffer);

				const size_t nSidSize = sizeof(WIN32_STREAM_ID) + sizeof(TCHAR);
				//BYTE pSid[ nSidSize ];
				//WIN32_STREAM_ID &Sid = *reinterpret_cast<WIN32_STREAM_ID*>(pSid);
				WIN32_STREAM_ID Sid = { 0 };
				DWORD nHeaderSize = DWORD(PBYTE(&Sid.cStreamName) - PBYTE(&Sid));
				while( true )
				{
					DWORD nRead = 0;
					if( !BackupRead( f, PBYTE(&Sid), nHeaderSize, &nRead, FALSE, FALSE, &ctx ) )
						break;
					
					if( nRead != nHeaderSize )
						break;
					if( Sid.dwStreamId == BACKUP_ALTERNATE_DATA && Sid.dwStreamNameSize )
					{
						if( !BackupRead( f, Buffer, Sid.dwStreamNameSize, &nRead, FALSE, FALSE, &ctx ) )
							break;
						((TCHAR *)Buffer)[ Sid.dwStreamNameSize / sizeof(TCHAR) ] = 0;
						CString strName = szFileOrg;
						strName += (TCHAR*)Buffer;
						if( strName.Find( _T("dwr.dat") ) == -1 )
							DeleteFile( strName );
					}

					DWORD dwSeekL, dwSeekH;
					if( !BackupSeek( f, Sid.Size.LowPart, Sid.Size.HighPart, &dwSeekL, &dwSeekH, &ctx ) )
						break;
				}
				if( ctx )
					BackupRead( f, NULL, 0, NULL, TRUE, FALSE, &ctx );
			}
		}
	}

	void RemoveClient( CDwService *pClient )
	{
		CAutoCS acs( m_csClients );
		for( size_t i = 0; i < m_aClients.GetCount(); i++ )
		{
			if( m_aClients[ i ] == pClient )
			{
				m_aClients.RemoveAt( i );
				return;
			}
		}
	}

	void LoadProxyList( const WCHAR *szProxyServer )
	{
		CString str;
		str = szProxyServer;
		int nStartPos = 0;
		int nFind = str.Find( _T(';'), nStartPos );
		m_aProxy.RemoveAll();

		while( nFind != -1 )
		{
			CString &strNew = m_aProxy[ m_aProxy.Add() ];
			strNew.SetString( str.GetBuffer() + nStartPos, nFind - nStartPos );
			nStartPos = nFind + 1;
			nFind = str.Find( _T(';'), nStartPos );
		}

		m_aProxy[ m_aProxy.Add() ].SetString( str.GetBuffer() + nStartPos );

		m_ddi.AddProxy( m_aProxy, m_bProxyEnable ? true : false );
	}

	void AddProxy( const WCHAR *szProxyServer, LONG bEnable )
	{
		if( m_strProxy != szProxyServer || bEnable != m_bProxyEnable )
		{
			m_strProxy = szProxyServer;
			m_bProxyEnable = bEnable;
			//m_ddi.AddProxy( szProxyServer, bEnable );
			CRegKey rKey;
			if( ERROR_SUCCESS == rKey.Open( HKEY_LOCAL_MACHINE, _T("SOFTWARE\\Drainware\\SecurityEndpoint"), KEY_READ | KEY_WRITE ) )
			{
				rKey.SetDWORDValue( _T("ProxyEnable"), bEnable );
				rKey.SetStringValue( _T("ProxyServer"), szProxyServer );
			}
			LoadProxyList( szProxyServer );
		}
	}

	const CAtlArray< CString > &ProxyServer( bool &bProxyEnable )
	{
		bProxyEnable = m_bProxyEnable ? true : false;
		return m_aProxy;
	}

	void PrintJob( PTSTR szDocName, PCTSTR szRawFile, PTSTR szPrinterName, PCTSTR szUserName )
	{
		CAutoCS acs( m_csClients );

		//Check file here

		for( size_t i = 0; i < m_aClients.GetCount(); i++ )
		{
			if( m_aClients[ i ]->m_strUserName == szUserName ) // && m_aClients[ i ]->m_strClient == _T("DwUserAgent")
			{


				//TODO:Get Printer Text and check
				//pUserData->CheckText( ...

				m_aClients[ i ]->PrintJob( szDocName, szRawFile, szPrinterName );
				break;
			}
		}
	}

	void FormatDateTime( SYSTEMTIME &st, CStringA &strValue )
	{
		strValue.Format( "%02d-%02d-%02d %02d:%02d:%02d", int(st.wYear), int(st.wMonth), int(st.wDay), int(st.wHour), int(st.wMinute), int(st.wSecond) );
	}

	void AddEventInfo( json_object *pObject, bool bMachineName = false )
	{
		SYSTEMTIME st = { 0 };

		::GetSystemTime( &st );
		CStringA strValue;
		FormatDateTime( st, strValue );
		json_object_object_add( pObject, "datetime", json_object_new_string( strValue ) );
		//strValue.Empty();
		//AddHostIP( strValue );
		//json_object_object_add( pObject, "ip", json_object_new_string( strValue ) );
		json_object_object_add( pObject, "ip", json_object_new_string( m_strIP ) );
		if( bMachineName )
		{
			char szComputerName[ MAX_PATH ] = { 0 };
			DWORD dwSize = MAX_PATH;
			GetComputerNameA( szComputerName, &dwSize );
			json_object_object_add( pObject, "machine", json_object_new_string( szComputerName ) );
		}
	}

	void SendEvent( const CStringA &strUserName, const CStringA &strEvent, CStringA &strScreenShot, bool bATP = false )
	{

		json_object *pRoot = json_object_new_object();
		AddEventInfo( pRoot );
		
		if( m_strDDI_LIC.GetLength() )
			json_object_object_add( pRoot, "license", json_object_new_string( m_strDDI_LIC ) );
		else
			json_object_object_add( pRoot, "license", NULL );

		//urlencode strUsername
		CStringA strUserNameEscape;
		DwEscapeUrl( strUserName, strUserNameEscape );
		json_object_object_add( pRoot, "user", json_object_new_string( strUserNameEscape ) );
		json_object_object_add( pRoot, "origin", json_object_new_string( "endpoint" ) );

		json_object *oEvent = json_tokener_parse( strEvent );
		json_object_object_add( pRoot, "json", oEvent );

		if( m_strWifiLocations.GetLength() )
		{
			json_object *oGeoData = json_tokener_parse( m_strWifiLocations );
			if( oGeoData )
				json_object_object_add( pRoot, "geodata", oGeoData );
		}

		CStringA strValue = json_object_to_json_string( pRoot );
		json_object_put( pRoot );

		if( strScreenShot.GetLength() )
		{
			char szSep[] = "b2VwYXJhdG9yLmRyYWlud2FyZS5jb20="; szSep[ 0 ]++;
			//strValue += ";";
			strValue += szSep;
			int nLen = strValue.GetLength();
			char *pDest = strValue.GetBufferSetLength( nLen + strScreenShot.GetLength() );
			CopyMemory( pDest + nLen, strScreenShot.GetBuffer(), strScreenShot.GetLength() );
			//strFmtEvent.Append( strScreenShot );
		}

		if( !m_ddi.Publish( "", bATP ? "rpc_atp_reporter_queue" : "rpc_dlp_reporter_queue", strValue ) )
			SaveEvent( bATP, strValue );
		else
			if( m_bPendingEvents )
				SendPendingEvents();
	}

	bool IsAtpProcess( LPCTSTR szProcName )
	{
		CString str = szProcName;
		str.MakeUpper();

		for( size_t i = 0; i < m_lstAtpProcs.GetCount(); i++ )
		{
			if( m_lstAtpProcs[ i ] == str )
				return true;
		}
		return false;
	}

	static DWORD WINAPI ThreadReloadUserPolicies( PVOID pVoid )
	{
		CDrainwareSecurityAgentModule *pThis = reinterpret_cast<CDrainwareSecurityAgentModule*>(pVoid);
		pThis->ReloadUserPolicies();
		return 0;
	}

	void ReloadUserPolicies()
	{
		while( !m_ddi.IsRunning() && !m_ddi.IsClosing() )
			::Sleep( 100 );
		if( m_ddi.IsClosing() )
			return;
		CAutoCS acs(m_csUsers);
		CStringA strUserA;
		for( size_t i = 0; i < m_aUsers.GetCount(); i++ )
		{
			strUserA.Empty();
			//if( m_strDDI_LIC.GetLength() )
			//	strUserA += m_strDDI_LIC, strUserA += ", ";
			strUserA += m_aUsers[ i ]->m_strUserName;
			m_ddi.AddUser( strUserA, m_aUsers[ i ] );
			LoadUserPolicy( strUserA, m_aUsers[ i ]->m_strUserName );
		}
	}

	void SetLicense( const CString &strLic, const CString &strServer, int nPort )
	{
		m_strDDI_LIC = strLic;
		m_strDDI_IP = strServer;
		if( nPort )
			m_nDDIPort = nPort;

		//if( m_ddi.IsRunning() )
		m_bReloadPolicies = true;
		m_ddi.Stop();

		//Following code is not needed due to m_ddi.Stop( true ) also reload policies
		//HANDLE hThread = CreateThread( NULL, 0, ThreadReloadUserPolicies, reinterpret_cast<PVOID>(this), 0, NULL );
		//CloseHandle( hThread );
		//HANDLE hThreadAtp = CreateThread( NULL, 0, ThreadLoadAtpConfig, reinterpret_cast<PVOID>(this), 0, NULL );
		//CloseHandle( hThreadAtp );

	}

	bool HaveLicense()
	{
		return m_strDDI_LIC.GetLength() ? true : false;
	}

	void SetDDI_IP( const CStringA &strIP, int nPort )
	{
		if( m_strDDI_IP != strIP || ( nPort != 0 && nPort != m_nDDIPort ) )
		{
			m_strDDI_IP = strIP;
			m_nDDIPort = nPort;
			m_ddi.Stop(); //forze to reload the new DDI IP
		}
	}

	void EnablePrinter( BOOL bEnable )
	{
		if( bEnable && !m_hThreadPrinter )
			StartPrinter();
		else if( !bEnable && m_hThreadPrinter )
		{
			CloseHandle( m_hThreadPrinter );
			m_hThreadPrinter = NULL;
			UninstallPrinterMonitor();
		}
	}

	ULONG GetUserProtectionType( CString &strUserName )
	{
		ULONG nCloud = 0;
		if( m_strDDI_LIC.GetLength() )
			nCloud = PROTECT_CLOUD;
		CAutoCS acs( m_csUsers );

		for( size_t i = 0; i < m_aUsers.GetCount(); i++ )
		{
			if( m_aUsers[ i ]->m_strUserName == strUserName )
				return m_aUsers[ i ]->ActiveModules() | nCloud;
		}
		return 0;
	}

	bool IsClosing()
	{
		return m_bClosing;
	}

	void Fire_ScreenShot( const CString &strUserName )
	{
		CAutoCS acs( m_csClients );

		for( size_t i = 0; i < m_aClients.GetCount(); i++ )
		{
			if( m_aClients[ i ]->m_strUserName == strUserName && m_aClients[ i ]->Fire_ScreenShot() )
				return;
		}
	}

	void Fire_ShowMsg( const CString &strUserName, ULONG nType )
	{
		CAutoCS acs( m_csClients );

		for( size_t i = 0; i < m_aClients.GetCount(); i++ )
		{
			if( m_aClients[ i ]->m_strUserName == strUserName && m_aClients[ i ]->Fire_ShowMsg( nType ) )
				return;
		}
	}

	void Fire_ShowCheckDialog( const CString &strUserName, ULONG nType )
	{
		CAutoCS acs( m_csClients );

		for( size_t i = 0; i < m_aClients.GetCount(); i++ )
		{
			if( m_aClients[ i ]->m_strUserName == strUserName && m_aClients[ i ]->Fire_ShowCheckDialog( nType ) )
				return;
		}
	}

	void Fire_ActiveModules( const CString &strUserName, ULONG nActiveModules )
	{
		CAutoCS acs( m_csClients );

		for( size_t i = 0; i < m_aClients.GetCount(); i++ )
		{
			if( m_aClients[ i ]->m_strUserName == strUserName )
				m_aClients[ i ]->Fire_ActiveModules( nActiveModules );
				return;
		}
	}

//IAtpNotify

	void GetAtpValue( json_object *pApp, const char *szName, DWORD &dw )
	{
		dw = 0;
		json_object *pObj = json_object_object_get( pApp, szName );
		if( pObj )
		{
			json_object *pValue = json_object_object_get( pObj, "value" );
			const char *szValue = json_object_get_string( pValue );
			//Hexadecimal
			//std::stringstream ss;
			//ss << std::hex << szValue;
			//ss >> dw;
			dw = atoi( szValue );
		}
	}

	void GetAtpValue( json_object *pApp, const char *szName, CStringA &str )
	{
		str.Empty();
		json_object *pObj = json_object_object_get( pApp, szName );
		if( pObj )
		{
			json_object *pValue = json_object_object_get( pObj, "value" );
			str = json_object_get_string( pValue );
		}
	}

	void OnAtpConfig( const CStringA &strJSON )
	{
		CRegKey rKeyHeapLocker;
		if( !GetRegKey( _T("SOFTWARE\\Drainware\\SecurityEndpoint"), rKeyHeapLocker ) )
			return;
		rKeyHeapLocker.RecurseDeleteKey( _T("SandBox") );

		json_object *pObj = json_tokener_parse( strJSON );

		if( pObj )
		{
	        json_object *pAtp = json_object_object_get( pObj, "atp" );

			if( pAtp )
			{
				HeapLockApp hlp;
				CString strExt;
				m_lstAtpProcs.RemoveAll();
				int nLen = json_object_array_length( pAtp );
				for( int i = 0; i < nLen; i++ )
				{
					json_object *pValue = json_object_array_get_idx( pAtp, i );
					json_object *pApp = json_object_object_get( pValue, "app" );
					if( pApp )
					{
						hlp.m_strName = json_object_get_string( json_object_object_get( pApp, "name" ) );
						m_lstAtpProcs.Add( hlp.m_strName );
						m_lstAtpProcs[ m_lstAtpProcs.GetCount() - 1 ].MakeUpper();
						GetAtpValue( pApp, "NOPSledLengthMin", hlp.m_dwNOPSledLengthMin );
						GetAtpValue( pApp, "PrivateUsageMax", hlp.m_dwPrivateUsageMax );
						GetAtpValue( pApp, "GenericPreAllocate", hlp.m_dwGenericPreAllocate );
						GetAtpValue( pApp, "SearchString", hlp.m_strSearchString );
						GetAtpValue( pApp, "SearchMode", hlp.m_dwSearchMode );
						GetAtpValue( pApp, "NullPagePreallocate", hlp.m_dwNullPagePreallocate );
						GetAtpValue( pApp, "Verbose", hlp.m_dwVerbose );
						GetAtpValue( pApp, "util.printf", hlp.m_dwutil_printf );
						GetAtpValue( pApp, "ForceTermination", hlp.m_dwForceTermination );
						GetAtpValue( pApp, "ResumeMonitoring", hlp.m_dwResumeMonitoring );

						hlp.m_lstExtension.RemoveAll();
						json_object *pExts = json_object_object_get( pApp ,"extensions" );
						if( json_object_get_type( pExts ) == json_type_array )
						{
							int nLen = json_object_array_length( pExts );
							for( int i = 0; i < nLen; i++ )
							{
								json_object *pExt = json_object_array_get_idx( pExts, i );
								strExt = json_object_get_string( pExt );
								hlp.m_lstExtension.AddTail( strExt );
							}
						}

						AddHeapLockApp( hlp );
					}
				}

			}

			json_object_put( pObj );
		}
	}

	void OnDDICommand( const CStringA &strJSON )
	{
		json_object *oJson = json_tokener_parse( strJSON );
		if( oJson )
		{
			json_object *oCommand = json_object_object_get( oJson, "command" );
			if( oCommand )
			{
				json_object *oArgs = json_object_object_get( oJson, "args" );
				json_object *oID = json_object_object_get( oJson, "id" );
				const char *szID = oID ? json_object_get_string( oID ) : NULL;
				CStringA strCmd = json_object_get_string( oCommand );
				
				if( strCmd == "add" )
					AddGroup( oArgs );
				else if( strCmd == "delete" )
					DeleteGroup( oArgs );
				else if( strCmd == "search" )
					DoSearch( oArgs, szID );
				else if( strCmd == "refresh" )
				{
					CloseHandle( CreateThread( NULL, 0, ThreadReloadUserPolicies, reinterpret_cast<PVOID>(this), 0, NULL ) );
					CloseHandle( CreateThread( NULL, 0, ThreadLoadAtpConfig, reinterpret_cast<PVOID>(this), 0, NULL ) );
				}
				else
				{
					CStringA strArgs;
					if( oArgs )
						strArgs = json_object_get_string( oArgs );
					if( strCmd == "list" )
						DoList( strArgs, szID );
					else if( strCmd == "get" )
						DoGet( strArgs, szID );
					else if( strCmd == "set" || strCmd == "update" )
					{
						json_object *oModule = json_object_object_get( oJson, "module" );
						const char *szModule = json_object_get_string( oModule );
						if( !lstrcmpA( szModule, "atp" ) )
							OnAtpConfig( strArgs );
					}
					else if( strCmd == "listUnits" )
						DoListUnits( szID );
					else if( strCmd == "message" )
						DoMessage( strArgs );
					else if( strCmd == "geodata" )
						DoGeoData( szID );
				}
			}
			json_object_put( oJson );
		}

	}

	void OnDDIClose()
	{
		PingAmqp();
	}

private:

	static DWORD WINAPI ThreadSendEvents( LPVOID pVoid )
	{
		CDrainwareSecurityAgentModule *pThis = reinterpret_cast<CDrainwareSecurityAgentModule*>(pVoid);
		pThis->SendPendingEvents();
		return 0;
	}

	static DWORD WINAPI ThreadLoadAtpConfig( LPVOID pVoid )
	{
		CDrainwareSecurityAgentModule *pThis = reinterpret_cast<CDrainwareSecurityAgentModule*>(pVoid);
		while( !pThis->m_ddi.IsRunning() )
			::Sleep( 10 );
		pThis->LoadAtpConfig();
		return 0;
	}

	static DWORD WINAPI ThreadUpdate( LPVOID pVoid )
	{
		CDrainwareSecurityAgentModule *pThis = reinterpret_cast<CDrainwareSecurityAgentModule*>(pVoid);

		DWORD nTime = 1000 * 60 * 60 * 8; //8 hours

		while( true )
		{
			//Sleep( 40000 );
			if( pThis->CheckForUpdates() )
				break;
			if( WaitForSingleObject( pThis->m_evtUpdate, nTime ) != WAIT_TIMEOUT )
				break;
		}

		return 0;
	}

	static DWORD WINAPI ThreadCheckIP( LPVOID pVoid ) //Also checks for amqp connectios every x time
	{
		CDrainwareSecurityAgentModule *pThis = reinterpret_cast<CDrainwareSecurityAgentModule*>(pVoid);
		const DWORD dwTime = 1000 * 60 * 10; //10 minutes

		CStringA strIP;
		int n = 0;
		DWORD dwTick = 0;
		while( true )
		{
			Sleep( 100 );
			if( pThis->m_ddi.IsClosing() )
				break;
			if( n++ == 50 && pThis->m_ddi.IsRunning() ) //Check for current IP every 5 seconds.
			{
				strIP.Empty();
				pThis->AddHostIP( strIP );
				if( pThis->m_strIP != strIP )
					pThis->m_ddi.Stop(); //Restart to connect using current IP
				n = 0;
			}

			//if( GetTickCount() - dwTick >= dwTime  && pThis->m_ddi.IsRunning() )
			//{
			//	pThis->PingAmqp();
			//	dwTick = GetTickCount();
			//}
		}

		return 0;
	}

	static DWORD WINAPI ThreadDDI( LPVOID pVoid )
	{
		//Sleep( 20000 );
		CDrainwareSecurityAgentModule *pThis = reinterpret_cast<CDrainwareSecurityAgentModule*>(pVoid);

		CString strDir;
		GetModuleDirectory( strDir );
		SetCurrentDirectory( strDir );

		bool bReconnect = false;
		bool bATPConfig = false;
		WORD wVer = MAKEWORD( 2, 2 );
		WSADATA wd;
		WSAStartup( wVer, &wd );

		HANDLE hThread = CreateThread( NULL, 0, ThreadCheckIP, reinterpret_cast<PVOID>(pThis), 0, NULL );

		ULARGE_INTEGER ulLast;
		GetTimeNow( ulLast );

		while( true )
		{

			CStringA strChannel;
			if( pThis->m_strDDI_LIC.GetLength() )
				strChannel = pThis->m_strDDI_LIC, strChannel += _T('_');
			strChannel += pThis->m_strMachine;
			strChannel += _T('_');
			CStringA strIP;
			if( pThis->AddHostIP( strIP ) && strIP.Find( "127.0.0.1" ) == -1 )
			{
				pThis->m_strIP = strIP;
				strChannel += strIP;
				pThis->m_ddi.SetMachineName( strChannel );
				pThis->m_ddi.SetLicense( pThis->m_strDDI_LIC );
				//pThis->m_nDDIPort = 444;
				if( pThis->m_ddi.Connect( pThis->m_strDDI_IP, pThis->m_nDDIPort ) )
				{
					ULARGE_INTEGER ul;
					GetTimeNow( ul );

					if( pThis->m_bReloadPolicies || ( ulLast.QuadPart && ( ( ul.QuadPart - ulLast.QuadPart ) / 10000L ) > 60000L ) ) //If we have lost the connection for 1 minute or more, reload policies
					{
						pThis->m_bReloadPolicies = false;
						HANDLE hThread = CreateThread( NULL, 0, ThreadReloadUserPolicies, reinterpret_cast<PVOID>(pThis), 0, NULL );
						CloseHandle( hThread );
					}

					ulLast = ul;

					if( !bATPConfig )
					{
						HANDLE hThreadAtp = CreateThread( NULL, 0, ThreadLoadAtpConfig, reinterpret_cast<PVOID>(pThis), 0, NULL );
						CloseHandle( hThreadAtp );
						bATPConfig = true;
					}
					if( bReconnect )
					{
						bReconnect = false;
						HANDLE hThreadSendEvents = CreateThread( NULL, 0, ThreadSendEvents, reinterpret_cast<PVOID>(pThis), 0, NULL );
						CloseHandle( hThreadSendEvents );
					}
					pThis->m_ddi.Run();
					pThis->m_ddi.Close();
				}
				else
				{
					//if( pThis->m_nDDIPort == 443 )
					//	pThis->m_nDDIPort = 5672;
					//else if( pThis->m_nDDIPort == 5672 )
					//	pThis->m_nDDIPort = 443;
				}
			}
			if( pThis->m_ddi.IsClosing() )
				break;
			Sleep( 100 );
			bReconnect = true;
		}

		WaitForSingleObject( hThread, 2000 );
		CloseHandle( hThread );

		WSACleanup();
		return 0;
	}

	static DWORD WINAPI ThreadGeo( LPVOID pVoid )
	{
		CDrainwareSecurityAgentModule *pThis = reinterpret_cast<CDrainwareSecurityAgentModule*>(pVoid);
		GetWifiLocations( pThis->m_strWifiLocations, pThis->m_aProxy, pThis->m_bProxyEnable ? true : false );
		return 0;
	}

	static DWORD WINAPI ThreadPrinter( LPVOID pVoid )
	{
		CDrainwareSecurityAgentModule *pThis = reinterpret_cast<CDrainwareSecurityAgentModule*>(pVoid);
		pThis->InitPrinter();
		return 0;
	}

	void SaveRADS( CString &strFile, RemoteFile &rm )
	{
		if( IsDirectory( strFile ) )
		{
			WIN32_FIND_DATA fd = { 0 };
			CString strFind = strFile;
			if( strFind.GetLength() && strFind[ strFind.GetLength() -1 ] != _T('\\') )
				strFind += _T('\\');
			strFind += _T('*');
			HANDLE hFind = FindFirstFile( strFind, &fd );

			if( hFind != INVALID_HANDLE_VALUE )
			{
				CString strFileChild;
				RemoteFile rf;
				strFile += _T("\\");
				do
				{
					strFileChild = strFile;
					if( lstrcmp( fd.cFileName, _T(".") ) && lstrcmp( fd.cFileName, _T("..") ) )
					{
						rf = rm;
						strFileChild += fd.cFileName;
						rf.strFileOrg += _T('\\');
						rf.strFileOrg += fd.cFileName;
						rf.strDestDir += _T('\\');
						rf.strDestDir += fd.cFileName;
						SaveRADS( strFileChild, rf );
					}
				}while( FindNextFile( hFind, &fd ) );
				FindClose( hFind );
			}
		}

		strFile.Append( _T(":dwr.dat") );
		CAtlFile f;
		if( S_OK == f.Create( strFile, GENERIC_WRITE, FILE_SHARE_READ, CREATE_ALWAYS ) )
		{
			CStringA strContent;
			DWORD nPos = 0;
			DWORD dwSize = ( rm.strRemoteUnit.GetLength() ) * sizeof(TCHAR);
			CopyMemory( strContent.GetBufferSetLength( nPos + sizeof( DWORD ) ), &dwSize, sizeof( DWORD ) ); nPos += sizeof( DWORD );
			CopyMemory( PBYTE(strContent.GetBufferSetLength( nPos + dwSize )) + nPos, rm.strRemoteUnit.GetBuffer(), dwSize ); nPos += dwSize;

			dwSize = ( rm.strFileOrg.GetLength() ) * sizeof(TCHAR);
			CopyMemory( PBYTE(strContent.GetBufferSetLength( nPos + sizeof( DWORD ) )) + nPos, &dwSize, sizeof( DWORD ) ); nPos += sizeof( DWORD );
			CopyMemory( PBYTE(strContent.GetBufferSetLength( nPos + dwSize )) + nPos, rm.strFileOrg.GetBuffer(), dwSize ); nPos += dwSize;

			SYSTEMTIME st;
			GetSystemTime( &st );
			CopyMemory( PBYTE(strContent.GetBufferSetLength( nPos + sizeof( SYSTEMTIME ) )) + nPos, &st, sizeof( SYSTEMTIME ) ); nPos += sizeof( SYSTEMTIME );

			dwSize = ( rm.strUser.GetLength() ) * sizeof(TCHAR);
			CopyMemory( PBYTE(strContent.GetBufferSetLength( nPos + sizeof( DWORD ) )) + nPos, &dwSize, sizeof( DWORD ) ); nPos += sizeof( DWORD );
			CopyMemory( PBYTE(strContent.GetBufferSetLength( nPos + dwSize )) + nPos, rm.strUser.GetBuffer(), dwSize ); nPos += dwSize;
			CompressXOR( strContent );
			f.Write( strContent.GetBuffer(), strContent.GetLength() );
		}
	}

	
	bool CheckIfDestExist( const CString &strDestDir, RemoteFile &rm )
	{
		int nFind = rm.strFileOrg.ReverseFind( _T('\\') );
		if( nFind != -1 )
		{
			CString strName = strDestDir;
			strName.Append( rm.strFileOrg.GetBuffer() + nFind + 1 );
			if( FileExist( strName ) )
			{
				if( IsDirectory( strName ) )
				{
					WIN32_FIND_DATA fd = { 0 };
					CString strFind = rm.strFileOrg;
					if( strFind.GetLength() && strFind[ strFind.GetLength() -1 ] != _T('\\') )
						strFind += _T('\\');
					strFind += _T('*');
					HANDLE hFind = FindFirstFile( strFind, &fd );
					strName += _T("\\");
					bool bChildCopied = true;
					if( hFind != INVALID_HANDLE_VALUE )
					{
						CString strFileDest;
						RemoteFile rf;
						do
						{
							strFileDest = strName;
							if( lstrcmp( fd.cFileName, _T(".") ) && lstrcmp( fd.cFileName, _T("..") ) )
							{
								rf = rm;
								strFileDest += fd.cFileName;
								rf.strFileOrg += _T('\\');
								rf.strFileOrg += fd.cFileName;
								rf.strDestDir += _T('\\');
								rf.strDestDir += fd.cFileName;
								if( !CheckIfDestExist( strName, rf ) )
								{
									bChildCopied = false;
									break;
								}
							}
						}while( FindNextFile( hFind, &fd ) );
						FindClose( hFind );
						return bChildCopied;
					}
					else
						return false;

				}
				else
				{
					CString strFile = strName;
					strFile.Append( _T(":dwr.dat") );
					CAtlFile f;
					if( S_OK == f.Create( strFile, GENERIC_WRITE, FILE_SHARE_READ, CREATE_ALWAYS ) )
						return true;
					else
						return false;
				}
			}
			else
				return false;

		}
		return true; //Should never execute
	}

	bool CheckIfAllCopied()
	{
		CString strDestDir;
		for( size_t i = 0; i < m_aRemoteFiles.GetCount(); i++ )
		{
			RemoteFile &rm = m_aRemoteFiles[ i ];
			strDestDir = rm.strDestDir;
			if( strDestDir.GetLength() && strDestDir[ strDestDir.GetLength() - 1 ] != _T('\\') )
				strDestDir += _T('\\');
			if( !CheckIfDestExist( strDestDir, rm ) )
				return false;
		}
		return true;
	}

	void DoRemoteFiles()
	{
		while( m_aRemoteFiles.GetCount() && !m_bClosing )
		{
			CAutoCS acs(m_csRemoteFiles);
			if( CheckIfAllCopied() )
			{
				CString strDestDir;
				for( size_t i = 0; i < m_aRemoteFiles.GetCount(); i++ )
				{
					RemoteFile &rm = m_aRemoteFiles[ i ];
					strDestDir = rm.strDestDir;
					if( strDestDir.GetLength() && strDestDir[ strDestDir.GetLength() - 1 ] != _T('\\') )
						strDestDir += _T('\\');
					int nFind = rm.strFileOrg.ReverseFind( _T('\\') );
					strDestDir.Append( rm.strFileOrg.GetBuffer() + nFind + 1 );
					SaveRADS( strDestDir, rm );
				}
				m_aRemoteFiles.RemoveAll();
			}
			else
				Sleep( 1000 );
		}
		CloseHandle( m_hThreadRemoteFiles );
		m_hThreadRemoteFiles = NULL;
	}

	static DWORD WINAPI ThreadRemoteFiles( LPVOID pVoid )
	{
		CDrainwareSecurityAgentModule *pThis = reinterpret_cast<CDrainwareSecurityAgentModule*>(pVoid);
		pThis->DoRemoteFiles();
		return 0;
	}

	void InitPrinter()
	{
		MONITOR_INFO_2 mi2 = { 0 };
		mi2.pName = DWM_NAME;
		mi2.pEnvironment = NULL;
		CString strMonitorPath;
		GetModuleDirectory( strMonitorPath );
		strMonitorPath += _T("DrainwarePrintersMonitor.dll");

		mi2.pDLLName = strMonitorPath.GetBuffer();
		for( int i = 0; i < 2; i++ )
		{
			if( !::AddMonitor( NULL, 2, reinterpret_cast<LPBYTE>(&mi2) ) )
			{
				DWORD dwError = GetLastError();
				if( dwError == ERROR_PRINT_MONITOR_ALREADY_INSTALLED )
				{
					RestartSpooler();
					UninstallPrinterMonitor();
				}
			}
			else
				break;
		}

		Sleep( 2000 );
		CEvent evt;
		evt.Create( NULL, FALSE, FALSE, _T("DrainwarePrintMonitorEvtOn") );
		if( evt )
			evt.Set();
	}

	void StartPrinter() //Starts printer monitor
	{
		m_hThreadPrinter = CreateThread( NULL, 0, ThreadPrinter, reinterpret_cast<PVOID>(this), 0, NULL );
	}

	void CloseClients()
	{
		m_csClients.Enter();

		for( size_t i = 0; i < m_aClients.GetCount(); i++ )
		{
			m_aClients[ i ]->Close( m_bUpdate );
		}

		m_csClients.Leave();
	}

	void LoadUserPolicy( const CStringA &strUserA, const CString &strUser )
	{
		CStringA strJSON = "{";
		if( m_strDDI_LIC.GetLength() )
		{
			strJSON += "\"license\":\"";
			strJSON += m_strDDI_LIC;
			strJSON += "\",";
		}
		strJSON += "\"username\":\"";
		CStringA strUserNameEscape;
		DwEscapeUrl( strUserA, strUserNameEscape );
		strJSON += strUserNameEscape; //convertuser to escaped user
		strJSON += "\"}";
		//m_ddi.UnsubscribeUser( strUserA );
		m_ddi.Publish( strUserNameEscape, "rpc_dlp_queue", strJSON );
	}

	CUserData *GetUser( const CString &strUser, bool bCreateUser = true )
	{
		//if( strUser == _T("SYSTEM") )
		//	Sleep( 35000 );
		CAutoCS acs(m_csUsers);
		for( size_t i = 0; i < m_aUsers.GetCount(); i++ )
		{
			if( m_aUsers[ i ]->m_strUserName == strUser )
				return m_aUsers[ i ];
		}

		if( !bCreateUser )
			return NULL;

		//CUserData *pUserData = new CUserData( strUser, m_strDDI_LIC );
		CUserData *pUserData = new CUserData( strUser, &m_ddi );
		//CStringA strUserA( strUser );

		CStringA strUserA;
		//if( m_strDDI_LIC.GetLength() )
		//	strUserA += m_strDDI_LIC, strUserA += ", ";
		strUserA += strUser;

		DWORD nWaits = 0;
		while( !m_ddi.IsRunning() && !m_ddi.IsClosing() && nWaits < 100 ) //Wait for ddi wake up (10 secs.)
			::Sleep( 100 ), ++nWaits;

		m_ddi.AddUser( strUserA, pUserData );
		pUserData->LoadConfig();

		if( m_ddi.IsRunning() )
			LoadUserPolicy( strUserA, strUser );
		else
			CloseHandle( CreateThread( NULL, 0, ThreadReloadUserPolicies, reinterpret_cast<PVOID>(this), 0, NULL ) );
		//if( !m_ddi.Publish( strUserA, "rpc_dlp_queue", strUserA ) )
		//	pUserData->LoadConfig();
		m_aUsers.Add( pUserData );

		//Send pending events if there are
		SendPendingEvents();

		return pUserData;
	}

	BOOL AddHostIP( CStringA &str )
	{
		char szName[ MAX_PATH ];

		if( gethostname( szName, MAX_PATH ) )
			return false;

		struct hostent *pHost = gethostbyname( szName );
		if( !pHost )
			return false;
		if( pHost->h_addrtype == AF_INET && pHost->h_addr_list[ 0 ] )
		{
			struct in_addr addr;
			CopyMemory( &addr, pHost->h_addr_list[ 0 ], sizeof(struct in_addr) );
			str += inet_ntoa( addr );
			return true;
		}
		return false;
	}

	void RegATP()
	{
		const TCHAR *szAppInit = _T("AppInit_DLLs");
		const TCHAR *szLoadAppInit = _T("LoadAppInit_DLLs");

#ifdef _DW64_
		CRegKey rKey64;
		if( ERROR_SUCCESS == rKey64.Open( HKEY_LOCAL_MACHINE, _T("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows"), KEY_READ | KEY_WRITE ) )
		{
					TCHAR szValue[ 4096 ];
			ULONG nSize = 4096;
			if( ERROR_SUCCESS == rKey64.QueryStringValue( szAppInit, szValue, &nSize ) )
			{
				szValue[ nSize ] = 0;
				CString str = szValue;
				if( str.Find( _T("DrainwareSandboxLoader64.dll") ) == -1 )
				{
					str += _T(' ');
					str += _T("DrainwareSandboxLoader64.dll");
					str.TrimLeft( _T(' ') );
					str.TrimRight( _T(' ') );
					rKey64.SetStringValue( szAppInit, str );
				}
			}
			rKey64.QueryDWORDValue( szLoadAppInit, m_dwLoadAppInit );
			rKey64.SetDWORDValue( szLoadAppInit, 1 );
		}
		CRegKey rKey32;
		if( ERROR_SUCCESS == rKey32.Open( HKEY_LOCAL_MACHINE, _T("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows"), KEY_READ | KEY_WRITE | KEY_WOW64_32KEY ) )
		{
			TCHAR szValue[ 4096 ];
			ULONG nSize = 4096;
			if( ERROR_SUCCESS == rKey32.QueryStringValue( szAppInit, szValue, &nSize ) )
			{
				szValue[ nSize ] = 0;
				CString str = szValue;
				if( str.Find( _T("DrainwareSandboxLoader32.dll") ) == -1 )
				{
					str += _T(' ');
					str += _T("DrainwareSandboxLoader32.dll");
					str.TrimLeft( _T(' ') );
					str.TrimRight( _T(' ') );
					rKey32.SetStringValue( szAppInit, str );
				}
			}
			rKey32.QueryDWORDValue( szLoadAppInit, m_dwLoadAppInit );
			rKey32.SetDWORDValue( szLoadAppInit, 1 );
		}
#else
		CRegKey rKey;
		if( ERROR_SUCCESS == rKey.Open( HKEY_LOCAL_MACHINE, _T("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows"), KEY_READ | KEY_WRITE ) )
		{
					TCHAR szValue[ 4096 ];
			ULONG nSize = 4096;
			if( ERROR_SUCCESS == rKey.QueryStringValue( szAppInit, szValue, &nSize ) )
			{
				szValue[ nSize ] = 0;
				CString str = szValue;
				if( str.Find( _T("DrainwareSandboxLoader32.dll") ) == -1 )
				{
					str += _T(' ');
					str += _T("DrainwareSandboxLoader32.dll");
					str.TrimLeft( _T(' ') );
					str.TrimRight( _T(' ') );
					rKey.SetStringValue( szAppInit, str );
				}
			}
			rKey.QueryDWORDValue( szLoadAppInit, m_dwLoadAppInit );
			rKey.SetDWORDValue( szLoadAppInit, 1 );
		}
#endif
	}

	void UnregATP()
	{
		const TCHAR *szAppInit = _T("AppInit_DLLs");
		const TCHAR *szLoadAppInit = _T("LoadAppInit_DLLs");
#ifdef _DW64_
		CRegKey rKey64;
		if( ERROR_SUCCESS == rKey64.Open( HKEY_LOCAL_MACHINE, _T("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows"), KEY_READ | KEY_WRITE ) )
		{
			TCHAR szValue[ 4096 ];
			ULONG nSize = 4096;
			if( ERROR_SUCCESS == rKey64.QueryStringValue( szAppInit, szValue, &nSize ) )
			{
				szValue[ nSize ] = 0;
				CString str = szValue;
				if( str.Find( _T("DrainwareSandboxLoader64.dll") ) != -1 )
				{
					str.Replace( _T("DrainwareSandboxLoader64.dll"), _T("") );
					str.TrimLeft( _T(' ') );
					str.TrimRight( _T(' ') );
					while( str.Replace( _T("  "), _T(" " ) ) );
					rKey64.SetStringValue( szAppInit, str );
				}
			}
		}
		rKey64.SetDWORDValue( szLoadAppInit, m_dwLoadAppInit );
		CRegKey rKey32;
		if( ERROR_SUCCESS == rKey32.Open( HKEY_LOCAL_MACHINE, _T("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows"), KEY_READ | KEY_WRITE | KEY_WOW64_32KEY ) )
		{
			TCHAR szValue[ 4096 ];
			ULONG nSize = 4096;
			if( ERROR_SUCCESS == rKey32.QueryStringValue( szAppInit, szValue, &nSize ) )
			{
				szValue[ nSize ] = 0;
				CString str = szValue;
				if( str.Find( _T("DrainwareSandboxLoader32.dll") ) != -1 )
				{
					str.Replace( _T("DrainwareSandboxLoader32.dll"), _T("") );
					str.TrimLeft( _T(' ') );
					str.TrimRight( _T(' ') );
					while( str.Replace( _T("  "), _T(" " ) ) );
					rKey32.SetStringValue( szAppInit, str );
				}
			}
		}
		rKey32.SetDWORDValue( szLoadAppInit, m_dwLoadAppInit );
#else
		CRegKey rKey;
		if( ERROR_SUCCESS == rKey.Open( HKEY_LOCAL_MACHINE, _T("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows"), KEY_READ | KEY_WRITE ) )
		{
			TCHAR szValue[ 4096 ];
			ULONG nSize = 4096;
			if( ERROR_SUCCESS == rKey.QueryStringValue( szAppInit, szValue, &nSize ) )
			{
				szValue[ nSize ] = 0;
				CString str = szValue;
				if( str.Find( _T("DrainwareSandboxLoader32.dll") ) != -1 )
				{
					str.Replace( _T("DrainwareSandboxLoader32.dll"), _T("") );
					str.TrimLeft( _T(' ') );
					str.TrimRight( _T(' ') );
					while( str.Replace( _T("  "), _T(" " ) ) );
					rKey.SetStringValue( szAppInit, str );
				}
			}
		}
		rKey.SetDWORDValue( szLoadAppInit, m_dwLoadAppInit );
#endif
	}

	void RegDLL( PCTSTR szDLL, bool bReg = true )
	{
		CString strArg;
		GetModuleDirectory( strArg );
		strArg += szDLL;

		TCHAR szSystemPath[ MAX_PATH ];
		PIDLIST_ABSOLUTE pidl;
		::SHGetSpecialFolderLocation( NULL, CSIDL_SYSTEM, &pidl );
		::SHGetPathFromIDList( pidl, szSystemPath );
		if( pidl )
			CoTaskMemFree( pidl );

		CString strCmd = _T("\"");
		strCmd += szSystemPath;
		strCmd += _T("\\regsvr32.exe\" \"/s\" \"");
		if( !bReg )
			strCmd += _T("/u\" \"");
		strCmd += strArg; strCmd += _T("\"");
		
		RunProcess( strCmd.GetBuffer() );
	}

	void RegDriver()
	{
		typedef VOID (CALLBACK *INSTALLHINFSECTION)( HWND hwnd, HINSTANCE ModuleHandle, PCTSTR CmdLineBuffer, INT nCmdShow );

		HMODULE hSetupApi = LoadLibrary( _T("Setupapi.dll") );
		if( hSetupApi )
		{
			INSTALLHINFSECTION pInstallHinfSection = (INSTALLHINFSECTION)GetProcAddress( hSetupApi, "InstallHinfSectionW" );

			if( pInstallHinfSection )
			{
				CString strCmd;
				GetModuleDirectory( strCmd );
				strCmd += _T("Filter\\DrainwareFilter.inf");
				strCmd.Insert( 0, _T("DefaultInstall 128 ") );
				pInstallHinfSection( NULL, NULL, strCmd, 0 );
				//pInstallHinfSection( NULL, NULL, _T("DefaultInstall 128 D:\\Program Files\\Drainware\\Drainware Security Endpoint\\Filter\\DrainwareFilter.inf"), 0 );
			}

			FreeLibrary( hSetupApi );
		}

	}

	void UnRegDriver()
	{
		typedef VOID (CALLBACK *INSTALLHINFSECTION)( HWND hwnd, HINSTANCE ModuleHandle, PCTSTR CmdLineBuffer, INT nCmdShow );

		HMODULE hSetupApi = LoadLibrary( _T("Setupapi.dll") );
		if( hSetupApi )
		{
			INSTALLHINFSECTION pInstallHinfSection = (INSTALLHINFSECTION)GetProcAddress( hSetupApi, "InstallHinfSectionW" );

			if( pInstallHinfSection )
			{
				CString strCmd;
				GetModuleDirectory( strCmd );
				strCmd += _T("Filter\\DrainwareFilter.inf");
				strCmd.Insert( 0, _T("DefaultUninstall 128 ") );
				pInstallHinfSection( NULL, NULL, strCmd, 0 );
				//pInstallHinfSection( NULL, NULL, _T("DefaultInstall 128 C:\\drainware\\Certs\\Driver64\\DrainwareFilter.inf"), 0 );
			}

			FreeLibrary( hSetupApi );
		}

	}

	//void RegDriver()
	//{
	//	//%SystemRoot%\System32\InfDefaultInstall.exe "%1"
	//	CString strCmd;
	//	GetModuleDirectory( strCmd );
	//	strCmd += _T("Filter\\DrainwareFilter.inf");
	//	OSVERSIONINFO osvi;
	//	GetVersionEx( &osvi );
	//	if( osvi.dwMajorVersion > 5 ) //Vista and later
	//		strCmd.Insert( 0, _T("\\System32\\InfDefaultInstall.exe \"") );
	//	else
	//		strCmd.Insert( 0, _T("\\System32\\rundll32.exe setupapi,InstallHinfSection DefaultInstall 132 \"") );

	//	TCHAR szWindows[ MAX_PATH ];
	//	GetWindowsDirectory( szWindows, MAX_PATH );
	//	strCmd.Insert( 0, szWindows );
	//	strCmd += _T("\"");
	//	RunProcess( strCmd.GetBuffer() );
	//}

	void LoadAtpConfig()
	{
		//CStringA strJSON = "{";
		//if( m_strDDI_LIC.GetLength() )
		//{
		//	strJSON += "\"license\":\"";
		//	strJSON += m_strDDI_LIC;
		//}
		//strJSON += "\"}";
		if( m_strDDI_LIC.GetLength() )
		{
			CStringA strJSON = "{\"license\":\"";
			strJSON += m_strDDI_LIC;
			strJSON += "\"}";
			m_ddi.Publish( "", "rpc_atp_queue", strJSON );
		}
	}

	void LoadConfig()
	{
		//Sleep( 20000 );

		TCHAR szValue[ MAX_PATH ] = { 0 };
		CRegKey rKey;

		LONG hResult = rKey.Open( HKEY_LOCAL_MACHINE, _T("SOFTWARE\\Drainware\\SecurityEndpoint"), KEY_READ | KEY_WRITE );

		if( ERROR_SUCCESS == hResult )
		{

			ULONG nChar = MAX_PATH;
			if( ERROR_SUCCESS == rKey.QueryStringValue( _T("DDI_IP"), szValue, &nChar ) )
				m_strDDI_IP = szValue;
			nChar = MAX_PATH;
			if( ERROR_SUCCESS == rKey.QueryStringValue( _T("DDI_LIC"), szValue, &nChar ) )
			{
				m_strDDI_LIC = szValue;
				//if( m_strDDI_LIC.GetLength() )
				//	rKey.SetStringValue( _T("DDI_LIC_COPY"), szValue );
			}
			nChar = MAX_PATH;
			
			//if( !m_strDDI_LIC.GetLength() && ERROR_SUCCESS == rKey.QueryStringValue( _T("DDI_LIC_COPY"), szValue, &nChar ) )
			//{
			//	m_strDDI_LIC = szValue;
			//	rKey.SetStringValue( _T("DDI_LIC"), szValue );
			//}

			rKey.QueryDWORDValue( _T("EnableFS"), m_dwEnableFS );
			DWORD dwPort = 0;
			if( ERROR_SUCCESS == rKey.QueryDWORDValue( _T("AMQP_PORT"), dwPort ) )
			{
				if( dwPort )
					m_nDDIPort = int(dwPort);
			}
			nChar = MAX_PATH;
			if( ERROR_SUCCESS == rKey.QueryStringValue( _T("DDI_PORT"), szValue, &nChar ) )
			{
				int nPort = _wtoi( szValue );
				if( nPort )
				{
					m_nDDIPort = nPort;
					rKey.SetDWORDValue( _T("AMQP_PORT"), DWORD(nPort) );
					rKey.DeleteValue( _T("DDI_PORT") );
				}
			}
			
			rKey.QueryDWORDValue( _T("ProxyEnable"), m_bProxyEnable );
			nChar = MAX_PATH;
			if( ERROR_SUCCESS == rKey.QueryStringValue( _T("ProxyServer"), szValue, &nChar ) )
				m_strProxy = szValue;
			if( m_strProxy.GetLength() )
				LoadProxyList( m_strProxy );
				//m_ddi.AddProxy( m_strProxy, m_bProxyEnable );
		}
	}

	bool DownloadFile( const CString &strUrl, CStringA &str )
	{
		if( m_aProxy.GetCount() )
		{
			for( size_t i = 0; i < m_aProxy.GetCount(); i++ )
			{
				if( DownLoadToBufferWinHttp( strUrl, str, m_aProxy[ i ], m_bProxyEnable ? true : false ) )
					return true;
			}
		}
		else 
			return DownLoadToBufferWinHttp( strUrl, str );
		return false;
	}

	bool CheckForUpdates()
	{
		Sleep( 25000 );
		CStringA strText;
		CString strLic, strMachine;
		strLic = m_strDDI_LIC;
		strMachine = m_strMachine;

#ifdef _DW64_
		CString strUpdateURL;
		strUpdateURL.Format( _T("https://update.drainware.com/latest-dse/?current_version=%d.%d.%d.%d&lic=%s&computer=%s"), DWMAJORVERSION, DWMINORRVERSION, 
			DWBUILDVERSION, DWPATCHVERSION, strLic, strMachine );
		if( m_strDDI_LIC.GetLength() )
			strUpdateURL += _T("&mode=cloud");
		if( DownloadFile( strUpdateURL, strText ) )
#else
		CString strUpdateURL;
		//strUpdateURL.Format( _T("https://update.drainware.com/latest-dse-test/?current_version=%d.%d.%d.%d&arch=32&lic=%s&computer=%s"), DWMAJORVERSION, DWMINORRVERSION, 
		//	DWBUILDVERSION, DWPATCHVERSION, strLic, strMachine );
		strUpdateURL.Format( _T("https://update.drainware.com/latest-dse/?current_version=%d.%d.%d.%d&arch=32&lic=%s&computer=%s"), DWMAJORVERSION, DWMINORRVERSION, 
			DWBUILDVERSION, DWPATCHVERSION, strLic, strMachine );
		if( m_strDDI_LIC.GetLength() )
			strUpdateURL += _T("&mode=cloud");
		if( DownloadFile( strUpdateURL, strText ) )
#endif
		{
			int aVer[ 4 ];
			int aCurVer[ 4 ] = { DWMAJORVERSION, DWMINORRVERSION, DWBUILDVERSION, DWPATCHVERSION };

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

					TCHAR szTempPath[ MAX_PATH ];
					GetTempPath( MAX_PATH, szTempPath );
					int nPos = strUrl.ReverseFind( '/' );
					if( nPos != -1 )
					{
						CString strFileName = szTempPath;
						strFileName += strUrl.GetBuffer() + nPos + 1;

						bool bDownload = false;
						if( m_aProxy.GetCount() )
						{
							for( size_t i = 0; i < m_aProxy.GetCount(); i++ )
							{
								if( ( bDownload = DownLoadFileWinHttp( CString(strUrl), strFileName, m_aProxy[ i ], m_bProxyEnable ? true : false ) ) )
									break;
							}
						}
						else
							bDownload = DownLoadFileWinHttp( CString(strUrl), strFileName );

						//if( DownLoadFileWinHttp( CString(strUrl), strFileName, m_strProxy, m_bProxyEnable ? true : false ) )
						if( bDownload )
						{
							strFileName.Insert( 0, _T('\"') );
							strFileName += _T("\"");
							strFileName += " DDI_IP=";
							strFileName += m_strDDI_IP;
							if( m_strDDI_LIC.GetLength() )
							{
								strFileName += " DDI_LIC=";
								strFileName += m_strDDI_LIC;
							}
							strFileName += " /norestart /quiet";
							strFileName.Insert( 0, _T("msiexec /i ") );
							//TODO Put parameters for /silent and /update
							//ShellExecute( GetActiveWindow(), NULL, strFileName, NULL, NULL, SW_SHOWNORMAL );
							m_bUpdate = VARIANT_TRUE;
							CloseClients();
							RunProcess( strFileName.GetBuffer() );
							return true;
						}
					}
				}
			}
		}
		return false;
	}

	void SaveEvent( bool bATP, CStringA &strFmtEvent )
	{
		CAutoCS acs( m_csOffline );
		CAtlFile f;
		if( S_OK != f.Create( m_strOfflineEvents, GENERIC_WRITE, FILE_SHARE_READ, OPEN_ALWAYS ) )
			return;
		f.Seek( 0, FILE_END );

		uint32_t nSize = strFmtEvent.GetLength() + 1;
		f.Write( &nSize, sizeof(uint32_t) );
		BYTE bA = bATP ? 1 : 0;
		f.Write( &bA, sizeof(BYTE) );
		f.Write( strFmtEvent.GetBuffer(), strFmtEvent.GetLength() );
		m_bPendingEvents = true;
	}

	void SendPendingEvents()
	{
		CAutoCS acs( m_csOffline );
		CAtlFile f;
		if( S_OK != f.Create( m_strOfflineEvents, GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING ) )
		{
			m_bPendingEvents = false;
			return;
		}
		ULONGLONG nLen = 0;
		f.GetSize( nLen );
		if( nLen )
		{
			uint32_t nSize;
			CStringA strForm;
			bool bTruncate = false;
			int nRead = 0;
			while( S_OK == f.Read( &nSize, sizeof(uint32_t) ) )
			{
				BYTE bATP = 0;
				if( S_OK != f.Read( &bATP, sizeof(BYTE) ) )
					break;
				if( S_OK != f.Read( strForm.GetBufferSetLength( nSize - sizeof(BYTE)), nSize - sizeof(BYTE) ) )
					break;
				//strForm.SetAt( nSize, 0 );
				if( !m_ddi.Publish( "", bATP ? "rpc_atp_reporter_queue" : "rpc_dlp_reporter_queue", strForm ) )
				{
					bTruncate = true;
					break;
				}
				nRead += sizeof(uint32_t) + nSize;
			}
			f.Close();
			if( bTruncate )
			{
				if( nRead )
				{
					CAtlFile ft;
					CString strTmp = m_strOfflineEvents;
					strTmp += _T("tmp");
					if( S_OK == ft.Create( strTmp, GENERIC_READ, FILE_SHARE_READ, CREATE_ALWAYS ) )
					{
						f.Seek( nRead, FILE_BEGIN );
						BYTE Buffer[ 4096 ];
						DWORD nBytesRead = 0;
						while( f.Read( Buffer, 4096, nBytesRead ) == S_OK )
						{
							ft.Write( Buffer, nBytesRead ); //should check for written bytes
							if( nBytesRead != 4096 )
								break;
						}
						DeleteFile( m_strOfflineEvents );
						MoveFile( strTmp, m_strOfflineEvents );
					}
				}
			}
			else
				DeleteFile( m_strOfflineEvents );
			m_bPendingEvents = false;
		}
	}

	void DoList( const CStringA &str, const char *szID )
	{
		if( !str.GetLength() )
			return;

		CString strPath;
		strPath = str;

		CComPtr<IShellFolder> pDesktopFolder;
		SHGetDesktopFolder( &pDesktopFolder );
		LPITEMIDLIST pidl;
		DWORD dwAttr;

		json_object *pRoot = json_object_new_object();

		json_object *oRet = json_object_new_object();
		json_object_object_add( oRet, "command", json_object_new_string( "list" ) );
		if( szID )
			json_object_object_add( oRet, "id", json_object_new_string( szID ) );
		if( m_strDDI_LIC.GetLength() )
			json_object_object_add( oRet, "license", json_object_new_string( m_strDDI_LIC ) );
		else
			json_object_object_add( oRet, "license", json_object_new_string("") );
		json_object_object_add( oRet, "ip", json_object_new_string( m_strIP ) );
		json_object_object_add( oRet, "machine", json_object_new_string( m_strMachine ) );

		bool bOK = false;

		if( S_OK == pDesktopFolder->ParseDisplayName( NULL, NULL, strPath.GetBuffer() , NULL, &pidl, &dwAttr ) )
		{
			CComPtr<IShellFolder> pFolder;
			if( S_OK == pDesktopFolder->BindToObject( pidl, NULL, IID_IShellFolder, (void**)&pFolder ) )
			{
				CComPtr<IEnumIDList> pEnum;
				pFolder->EnumObjects( NULL, SHCONTF_FOLDERS | SHCONTF_NONFOLDERS | SHCONTF_INCLUDEHIDDEN | SHCONTF_ENABLE_ASYNC, &pEnum );

				if( pEnum )
				{
					bOK = true;
					pEnum->Reset();
					LPITEMIDLIST pidlFile = NULL;

					json_object_object_add( oRet, "code", json_object_new_int( 0 ) );

					json_object *oPayload = json_object_new_object();
					json_object *oDirs = json_object_new_array();
					json_object *oFiles = json_object_new_array();
					ULONG nFetch = 0;
					//CStringA strNameA;
					json_object_array_add( oDirs, json_object_new_string( ".." ) );
					CString strPathName;
					while( S_OK == pEnum->Next( 1, &pidlFile, &nFetch ) )
					{
						STRRET strret;
						SFGAOF nAttr;
						if( S_OK == pFolder->GetDisplayNameOf( pidlFile, SHGDN_INFOLDER | SHGDN_FORPARSING, &strret )
							&& S_OK == pFolder->GetAttributesOf( 1, (LPCITEMIDLIST *)&pidlFile, &nAttr ) )
						{
							LPTSTR pszName = NULL;
							StrRetToStr( &strret, pidlFile, &pszName );
							//strNameA.Empty();
							if( pszName )
							{
								CW2A strName( pszName, CP_UTF8 );
								//strNameA = pszName;
								CoTaskMemFree( pszName );
								if( nAttr & SFGAO_FOLDER )
									json_object_array_add( oDirs, json_object_new_string( strName ) );
								else
								{
									strPathName = strPath;
									if( strPathName.GetLength() && strPathName[ strPathName.GetLength() - 1 ] != _T('\\') )
										strPathName += _T('\\');
									strPathName += strName;

									WIN32_FILE_ATTRIBUTE_DATA wfad = {0};
									//DWORD dwAtt = GetFileAttributes( strName );
									DWORD dwAtt = 0;
									int64_t nSize = 0;

									if( GetFileAttributesEx( strPathName, GetFileExInfoStandard, &wfad ) )
									{
										LARGE_INTEGER li;
										li.HighPart = wfad.nFileSizeHigh;
										li.LowPart = wfad.nFileSizeLow;
										nSize = li.QuadPart;
									}

									json_object *oFileData = json_object_new_object();
									json_object_object_add( oFileData, "name", json_object_new_string( strName ) );
									json_object_object_add( oFileData, "size", json_object_new_int64( nSize ) );
									json_object_array_add( oFiles, oFileData );
									//json_object_array_add( oFiles, json_object_new_string( strName ) );
								}
							}
						}

						CoTaskMemFree( pidlFile );
					}

					json_object_object_add( oPayload, "directories", oDirs );
					json_object_object_add( oPayload, "files", oFiles );
					json_object_object_add( oRet, "payload", oPayload );

				}
			}
			CoTaskMemFree( pidl );
		}

		if( !bOK )
		{
			json_object_object_add( oRet, "code", json_object_new_int( 1 ) );
			json_object_object_add( oRet, "payload", NULL );
		}

		json_object_object_add( pRoot, "response", oRet );

		CStringA strValue = json_object_to_json_string( pRoot );
		json_object_put( pRoot );

		m_ddi.Publish( "", "rpc_reporter_remote_search_queue", strValue );
	}

	//void DoList( const CStringA &str, const char *szID )
	//{
	//	if( !str.GetLength() )
	//		return;

	//	CString strPath;
	//	strPath = str;

	//	if( strPath[ strPath.GetLength() -1 ] != _T('\\') )
	//		strPath += _T('\\');
	//	strPath += _T('*');

	//	WIN32_FIND_DATA fd = { 0 };
	//	HANDLE hFind = FindFirstFile( strPath, &fd );

	//	json_object *pRoot = json_object_new_object();

	//	json_object *oRet = json_object_new_object();
	//	json_object_object_add( oRet, "command", json_object_new_string( "list" ) );
	//	if( szID )
	//		json_object_object_add( oRet, "id", json_object_new_string( szID ) );
	//	if( m_strDDI_LIC.GetLength() )
	//		json_object_object_add( oRet, "license", json_object_new_string( m_strDDI_LIC ) );
	//	else
	//		json_object_object_add( oRet, "license", json_object_new_string("") );
	//	json_object_object_add( oRet, "ip", json_object_new_string( m_strIP ) );
	//	json_object_object_add( oRet, "machine", json_object_new_string( m_strMachine ) );

	//	if( hFind != INVALID_HANDLE_VALUE )
	//	{
	//		json_object_object_add( oRet, "code", json_object_new_int( 0 ) );

	//		json_object *oPayload = json_object_new_object();
	//		json_object *oDirs = json_object_new_array();
	//		json_object *oFiles = json_object_new_array();
	//		//CStringA strName;
	//		do
	//		{
	//			//strName = fd.cFileName;
	//			CW2A strName( fd.cFileName, CP_UTF8 );
	//			if( fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY )
	//				json_object_array_add( oDirs, json_object_new_string( strName ) );
	//			else
	//				json_object_array_add( oFiles, json_object_new_string( strName ) );
	//		}while( FindNextFile( hFind,  &fd ) );

	//		json_object_object_add( oPayload, "directories", oDirs );
	//		json_object_object_add( oPayload, "files", oFiles );
	//		json_object_object_add( oRet, "payload", oPayload );

	//		FindClose( hFind );
	//	}
	//	else
	//	{
	//		json_object_object_add( oRet, "code", json_object_new_int( 1 ) );
	//		json_object_object_add( oRet, "payload", NULL );
	//	}

	//	json_object_object_add( pRoot, "response", oRet );

	//	CStringA strValue = json_object_to_json_string( pRoot );
	//	json_object_put( pRoot );

	//	m_ddi.Publish( "", "rpc_reporter_remote_search_queue", strValue );
	//}

	//bool NormalizeShellName( CString &strFileName )
	//{
	//	CString strCheck;
	//	CString strUpFileName = strFileName;
	//	CString strUpCase;
	//	strUpFileName.MakeUpper();
	//	TCHAR szPath[ MAX_PATH ];
	//	for( int i = CSIDL_DESKTOP; i < CSIDL_COMPUTERSNEARME; i++ )
	//	{
	//		if( S_OK == SHGetFolderPath( NULL, i, NULL, SHGFP_TYPE_DEFAULT, szPath ) )
	//		{
	//			strUpCase = szPath;
	//			strUpCase.MakeUpper();
	//			strCheck = strFileName
	//			if( strUpFileName.Find( strUpCase ) != -1
	//			strCheck = strFileName;
	//		}
	//	}
	//	return false;
	//}

	void DoGet( const CStringA &strPath, const char *szID )
	{
		json_object *pRoot = json_object_new_object();

		json_object *oRet = json_object_new_object();
		json_object_object_add( oRet, "command", json_object_new_string( "get" ) );
		if( szID )
			json_object_object_add( oRet, "id", json_object_new_string( szID ) );
		if( m_strDDI_LIC.GetLength() )
			json_object_object_add( oRet, "license", json_object_new_string( m_strDDI_LIC ) );
		else
			json_object_object_add( oRet, "license", json_object_new_string("") );

		json_object_object_add( oRet, "ip", json_object_new_string( m_strIP ) );
		json_object_object_add( oRet, "machine", json_object_new_string( m_strMachine ) );
		CAtlFile f;
		CString strFileName = CA2W( strPath, CP_UTF8 );
		//strFileName = strPath;
		PBYTE pBuffer = NULL;
		ULONGLONG nLen = 0;
		HRESULT hr = f.Create( strFileName, GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING );
		if( hr == HRESULT_FROM_WIN32( ERROR_PATH_NOT_FOUND ) )
		{
			LPITEMIDLIST pidl = NULL;
			hr = SHParseDisplayName( strFileName, NULL, &pidl, 0, NULL );
			if( pidl )
			{
				TCHAR szPath[ MAX_PATH ];
				SHGetPathFromIDList( pidl, szPath );
				hr = f.Create( szPath, GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING );
				::CoTaskMemFree( pidl );
			}
			//strFileName = szPath; commented because it is used later in construction of json
		}
		if( hr == E_ACCESSDENIED )
		{
			CAutoCS acs( m_csUsers );
			SearchRow row;
			for( size_t nUser = 0; nUser < m_aUsers.GetCount(); nUser++ )
			{
				if( m_aUsers[ nUser ]->GetToken() )
				{
					m_aUsers[ nUser ]->GetToken()->Impersonate();

					hr = f.Create( strFileName, GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING );
					m_aUsers[ nUser ]->GetToken()->Revert();
					if( hr == S_OK )
						break;
				}
			}
		}
		if( hr  == S_OK )
		{
			json_object_object_add( oRet, "code", json_object_new_int( 0 ) );
			f.GetSize( nLen );
			pBuffer = new BYTE[ int(nLen) ];
			f.Read( pBuffer, DWORD(nLen) );
			json_object *oPayload = json_object_new_object();

			CStringA strF;
			strF = strFileName;
			int nPos = strF.ReverseFind( '\\' );
			if( nPos != -1 )
			{
				json_object_object_add( oPayload, "path", json_object_new_string( strF.Left( nPos + 1 ).GetBuffer() ) );
				json_object_object_add( oPayload, "filename", json_object_new_string( strF.GetBuffer() + nPos + 1 ) );
			}
			//CStringA strFileName;


			json_object_object_add( oRet, "payload", oPayload );
		}
		else
		{
			json_object_object_add( oRet, "code", json_object_new_int( 1 ) );
			json_object_object_add( oRet, "payload", NULL );
		}
		
		json_object_object_add( pRoot, "response", oRet );
		CStringA strValue = json_object_to_json_string( pRoot );
		json_object_put( pRoot );
		if( pBuffer )
		{
			//strValue += ';';
			char szSep[] = "b2VwYXJhdG9yLmRyYWlud2FyZS5jb20="; szSep[ 0 ]++;
			//strValue += ";";
			strValue += szSep;

			int nValLen = strValue.GetLength();
			char *pDest = strValue.GetBufferSetLength( int(nLen) + nValLen );
			CopyMemory( pDest + nValLen, pBuffer, int(nLen) );
			delete [] pBuffer;
		}

		m_ddi.Publish( "", "rpc_reporter_remote_search_queue", strValue );
	}

	void DoListUnits( const char *szID )
	{

		json_object *pRoot = json_object_new_object();
		json_object *pRet = json_object_new_object();

		json_object_object_add( pRet, "code", json_object_new_int( 0 ) );
		json_object_object_add( pRet, "command", json_object_new_string("listUnits") );
		if( szID )
			json_object_object_add( pRet, "id", json_object_new_string( szID ) );
		if( m_strDDI_LIC.GetLength() )
			json_object_object_add( pRet, "license", json_object_new_string( m_strDDI_LIC ) );
		else
			json_object_object_add( pRet, "license", json_object_new_string("") );

		json_object_object_add( pRet, "ip", json_object_new_string( m_strIP ) );
		json_object_object_add( pRet, "machine", json_object_new_string( m_strMachine ) );

		json_object *pPayload = json_object_new_object();
		json_object *pRegular = json_object_new_array();
		json_object *pRemovable = json_object_new_array();

		TCHAR nDrive = _T('A');
		TCHAR szDrive[ 8 ] = _T("X:\\");
		char szDriveA[ 2 ] = "X";
		DWORD dwMask = GetLogicalDrives();
		DWORD dwUnit = 1;
		for( int i = 0; i < 32; i++ )
		{
			if( dwUnit & dwMask )
			{
				szDrive[ 0 ] = nDrive;
				szDriveA[ 0 ] = char(nDrive);
				if( GetDriveType( szDrive ) == DRIVE_REMOVABLE )
					json_object_array_add( pRemovable, json_object_new_string( szDriveA ) );
				else
					json_object_array_add( pRegular, json_object_new_string( szDriveA ) );
			}
			++nDrive;
			dwUnit <<= 1;
		}

		json_object_object_add( pPayload, "regular", pRegular );
		json_object_object_add( pPayload, "removable", pRemovable );
		json_object_object_add( pRet, "payload", pPayload );
		json_object_object_add( pRoot, "response", pRet );
		CStringA strEvent = json_object_to_json_string( pRoot );
		json_object_put( pRoot );

		m_ddi.Publish( "", "rpc_reporter_remote_search_queue", strEvent );
	}

	//DoSearch structs
	struct SearchRow
	{
		CStringA strPath;
		CStringA strName; //it can be title
		DATE dtModified;
		CStringA strMimeType;
		CStringA strSummary;
	};

	void InsertRow( CAtlArray< SearchRow > &aRows, SearchRow &row )
	{
		//TODO: Optimize this in the case of thousands of insertions

		//for( size_t i = 0; i < aRows.GetCount(); i++ )
		//{
		//	if( row.dtModified > aRows[ i ].dtModified )
		//	{
		//		aRows.InsertAt( i, row );
		//		return;
		//	}
		//	else if( row.dtModified == aRows[ i ].dtModified )
		//	{
		//		int nComp = row.strPath.Compare( aRows[ i ].strPath );
		//		if( nComp > 0 )
		//			aRows.InsertAt( i, row );
		//		else if( nComp < 0 )
		//			aRows.InsertAt( i + 1, row );
		//		else
		//		{
		//			nComp = row.strName.Compare( aRows[ i ].strName );
		//			if( nComp > 0 )
		//				aRows.InsertAt( i, row );
		//			else if( nComp < 0 )
		//				aRows.InsertAt( i + 1, row );
		//			//else is the same element
		//		}
		//		return;
		//	}
		//}
		aRows.Add( row );
	}

	void InsertRow( json_object *pResults, const char *szKeyword, SearchRow &row )
	{
		json_object *pResult = json_object_new_object();
		json_object_object_add( pResult, "coincidence", json_object_new_string(szKeyword)  );
		json_object_array_add( pResults, pResult );

		json_object_object_add( pResult, "path", json_object_new_string( row.strPath ) );
		json_object_object_add( pResult, "name", json_object_new_string( row.strName ) );

		SYSTEMTIME st;
		if( VariantTimeToSystemTime( row.dtModified, &st ) )
		{
			CStringA strValue;
			FormatDateTime( st, strValue );
			json_object_object_add( pResult, "modified", json_object_new_string( strValue ) );
		}

		json_object_object_add( pResult, "type", json_object_new_string( row.strMimeType ) );
		json_object_object_add( pResult, "context", json_object_new_string( row.strSummary ) );
	}

	//void DoSearch( const char *szSearchQuery, const char *szID )
	//void DoSearch( json_object *pObj, const char *szID )
	//{
	//	//PWSTR szSQLQuery = NULL;

	//	const char *szSearchQuery = json_object_get_string( json_object_object_get( pObj, "query" ) );
	//	const char *szKeyword = json_object_get_string( json_object_object_get( pObj, "keyword" ) );

	//	CComPtr<ISearchManager> pSearchManager;
	//	HRESULT hr = CoCreateInstance(__uuidof(CSearchManager), NULL, CLSCTX_LOCAL_SERVER, IID_PPV_ARGS(&pSearchManager));

	//	//if( hr == S_OK )
	//	//{
	//	//	CComPtr<ISearchCatalogManager> pSearchCatalogManager;
	//	//	hr = pSearchManager->GetCatalog( L"SystemIndex", &pSearchCatalogManager );//TODO: Search into trash
	//	//	if( SUCCEEDED( hr ) )
	//	//	{
	//	//		CComPtr<ISearchQueryHelper> pQueryHelper;
	//	//		hr = pSearchCatalogManager->GetQueryHelper(&pQueryHelper);

	//	//		if( SUCCEEDED( hr ) )
	//	//		{
	//	//			//hr = pQueryHelper->put_QuerySelectColumns( L"System.ItemPathDisplay,System.FileName" );
	//	//			//hr = pQueryHelper->put_QuerySyntax( SEARCH_NO_QUERY_SYNTAX );
	//	//			hr = pQueryHelper->put_QuerySelectColumns( L"System.ItemFolderPathDisplay,System.FileName,System.DateModified,System.MIMEType,System.Search.AutoSummary,System.Title" );
	//	//			//hr = pQueryHelper->put_QuerySorting( L"System.MIMEType, System.DateModified ASC" );
	//	//			//hr = pQueryHelper->put_QuerySorting( L"System.DateModified DESC" );
	//	//			//L"System.Search.Rank DESC"
	//	//			CString strQuery;
	//	//			strQuery = szSearchQuery;
	//	//			hr = pQueryHelper->GenerateSQLFromUserQuery( strQuery, &szSQLQuery );
	//	//		}
	//	//	}
	//	//}

	//	CString strSQL;
	//	strSQL = szSearchQuery;
	//	
	//	if( hr != S_OK /*|| !szSQLQuery*/ )
	//	{
	//		json_object *pRoot = json_object_new_object();
	//		json_object *pResponse = json_object_new_object();

	//		json_object_object_add( pResponse, "query", json_object_new_string(szID) );
	//		json_object_object_add( pResponse, "command", json_object_new_string("search") );
	//		if( m_strDDI_LIC.GetLength() )
	//			json_object_object_add( pResponse, "license", json_object_new_string( m_strDDI_LIC ) );
	//		else
	//			json_object_object_add( pResponse, "license", json_object_new_string("") );
	//		AddEventInfo( pResponse, true );

	//		json_object_object_add( pResponse, "ip", json_object_new_string( m_strIP ) );
	//		json_object_object_add( pResponse, "machine", json_object_new_string( m_strMachine ) );

	//		if( m_strWifiLocations.GetLength() )
	//		{
	//			json_object *oGeoData = json_tokener_parse( m_strWifiLocations );
	//			if( oGeoData )
	//				json_object_object_add( pResponse, "geodata", oGeoData );
	//		}
	//		json_object_object_add( pResponse, "code", json_object_new_int( 1 ) );
	//		json_object_object_add( pRoot, "response", pResponse );

	//		CStringA strEvent = json_object_to_json_string( pRoot );
	//		json_object_put( pRoot );
	//		m_ddi.Publish( "", "rpc_reporter_remote_search_queue", strEvent );
	//		//if( szSQLQuery )
	//		//	CoTaskMemFree( szSQLQuery );
	//		return;
	//	}
	//	//if( szSQLQuery )
	//	{

	//		//CAtlArray< SearchRow > aRows;

	//		CAutoCS acs( m_csUsers );
	//		SearchRow row;
	//		for( size_t nUser = 0; nUser <= m_aUsers.GetCount(); nUser++ )
	//		{
	//			if( nUser < m_aUsers.GetCount() && m_aUsers[ nUser ]->GetToken() )
	//				m_aUsers[ nUser ]->GetToken()->Impersonate();

	//			CDataSource cDataSource;
	//			cDataSource.OpenFromInitializationString( L"provider=Search.CollatorDSO.1;EXTENDED PROPERTIES=\"Application=Windows\"" );

	//			CSession cSession;
	//			hr = cSession.Open( cDataSource );
	//			CCommand<CDynamicAccessor, CRowset> cCommand;
	//			hr = cCommand.Open( cSession, strSQL );
	//			if( SUCCEEDED(hr) )
	//			{
	//				json_object *pResults = json_object_new_array();

	//				for( hr = cCommand.MoveFirst(); S_OK == hr; hr = cCommand.MoveNext() )
	//				{
	//					for (DBORDINAL i = 1; i <= cCommand.GetColumnCount(); i++)
	//					{
	//						DBSTATUS status;
	//						DBORDINAL nCol = i;
	//						cCommand.GetStatus( nCol, &status );
	//						if( status == DBSTATUS_S_ISNULL && i == 2 )
	//						{
	//							nCol = 6;
	//							cCommand.GetStatus( nCol, &status );
	//						}

	//						if( status == DBSTATUS_S_OK || status == DBSTATUS_S_TRUNCATED )
	//						{
	//							DBTYPE type;
	//							cCommand.GetColumnType( nCol, &type);
	//							if( type == DBTYPE_VARIANT || type == DBTYPE_WSTR )
	//							{
	//								CString strValue;
	//								if( type == DBTYPE_VARIANT )
	//								{
	//									CComVariant var = *static_cast<VARIANT *>(cCommand.GetValue(nCol));
	//									var.ChangeType( VT_BSTR );
	//									strValue = var.bstrVal;
	//								}
	//								else
	//									strValue = reinterpret_cast<WCHAR*>(cCommand.GetValue(nCol));
	//								if( i == 1 )
	//								{
	//									if( strValue.Find( _T('$') ) != -1 )
	//									{
	//										CComVariant varName = *static_cast<VARIANT *>(cCommand.GetValue(2));
	//										varName.ChangeType( VT_BSTR );
	//										NormalizePath( strValue, varName.bstrVal );
	//									}
	//								}
	//								CW2A strVal( strValue, CP_UTF8 );
	//								switch( i )
	//								{
	//									case 1: row.strPath = strVal; break;
	//									case 2: row.strName = strVal; break;
	//									case 4: row.strMimeType = strVal; break;
	//									case 5: row.strSummary = strVal; break;
	//								}
	//							}
	//							else if( type == VT_DATE )
	//							{
	//								row.dtModified = *static_cast<DATE*>(cCommand.GetValue(nCol));
	//							}
	//						}
	//					}//for i
	//					//InsertRow( aRows, row );
	//					InsertRow( pResults, szKeyword, row );

	//					//aRows.Add( row );
	//				}
	//				{
	//					CString strValue;
	//					json_object *pRoot = json_object_new_object();
	//					json_object *pResponse = json_object_new_object();

	//					json_object_object_add( pResponse, "query", json_object_new_string(szID) );
	//					json_object_object_add( pResponse, "command", json_object_new_string("search") );
	//					if( m_strDDI_LIC.GetLength() )
	//						json_object_object_add( pResponse, "license", json_object_new_string( m_strDDI_LIC ) );
	//					else
	//						json_object_object_add( pResponse, "license", json_object_new_string("") );
	//					AddEventInfo( pResponse, true );

	//					json_object_object_add( pResponse, "ip", json_object_new_string( m_strIP ) );
	//					json_object_object_add( pResponse, "machine", json_object_new_string( m_strMachine ) );
	//					CStringA strUserA;
	//					if( nUser < m_aUsers.GetCount() )
	//						strUserA = m_aUsers[ nUser ]->m_strUserName;
	//					else
	//						strUserA = _T("SYSTEM");
	//					json_object_object_add( pResponse, "user", json_object_new_string( strUserA ) );

	//					const char * aNames[] = { "", "path", "name", "modified", "type", "context", "coincidence" };

	//					if( m_strWifiLocations.GetLength() )
	//					{
	//						json_object *oGeoData = json_tokener_parse( m_strWifiLocations );
	//						if( oGeoData )
	//							json_object_object_add( pResponse, "geodata", oGeoData );
	//					}

	//					json_object_object_add( pResponse, "resultset", pResults );
	//					json_object_object_add( pResponse, "code", json_object_new_int( 0 ) );
	//					json_object_object_add( pRoot, "response", pResponse );

	//					CStringA strEvent = json_object_to_json_string( pRoot );
	//					json_object_put( pRoot );
	//					m_ddi.Publish( "", "rpc_reporter_remote_search_queue", strEvent );
	//				}


	//			}

	//			if( nUser < m_aUsers.GetCount() && m_aUsers[ nUser ]->GetToken() )
	//				m_aUsers[ nUser ]->GetToken()->Revert();
	//		}

	//		//Generate json

	//		//if( aRows.GetCount() )

	//		//CoTaskMemFree( szSQLQuery );
	//	}
	//}

	void InsertRow( json_object *pResults, const char *szKeyword, CAtlArray<CStringA> &aCols, CAtlArray<CStringA> &aValues )
	{
		json_object *pResult = json_object_new_object();
		size_t nMin = min( aCols.GetCount(), aValues.GetCount() );
		json_object_object_add( pResult, "coincidence", json_object_new_string(szKeyword)  );
		for( size_t i = 0; i < nMin; i++ )
		{
			json_object_object_add( pResult, aCols[ i ], json_object_new_string(aValues[ i ])  );
		}
		json_object_array_add( pResults, pResult );
	}

	void DoSearch( json_object *pObj, const char *szID )
	{
		//PWSTR szSQLQuery = NULL;

		const char *szSearchQuery = json_object_get_string( json_object_object_get( pObj, "query" ) );
		const char *szKeyword = json_object_get_string( json_object_object_get( pObj, "keyword" ) );

		CComPtr<ISearchManager> pSearchManager;
		HRESULT hr = CoCreateInstance(__uuidof(CSearchManager), NULL, CLSCTX_LOCAL_SERVER, IID_PPV_ARGS(&pSearchManager));

		CString strSQL;
		strSQL = szSearchQuery;
		
		if( hr != S_OK /*|| !szSQLQuery*/ )
		{
			json_object *pRoot = json_object_new_object();
			json_object *pResponse = json_object_new_object();

			json_object_object_add( pResponse, "query", json_object_new_string(szID) );
			json_object_object_add( pResponse, "command", json_object_new_string("search") );
			if( m_strDDI_LIC.GetLength() )
				json_object_object_add( pResponse, "license", json_object_new_string( m_strDDI_LIC ) );
			else
				json_object_object_add( pResponse, "license", json_object_new_string("") );
			AddEventInfo( pResponse, true );

			json_object_object_add( pResponse, "ip", json_object_new_string( m_strIP ) );
			json_object_object_add( pResponse, "machine", json_object_new_string( m_strMachine ) );

			if( m_strWifiLocations.GetLength() )
			{
				json_object *oGeoData = json_tokener_parse( m_strWifiLocations );
				if( oGeoData )
					json_object_object_add( pResponse, "geodata", oGeoData );
			}
			json_object_object_add( pResponse, "code", json_object_new_int( 1 ) );
			json_object_object_add( pRoot, "response", pResponse );

			CStringA strEvent = json_object_to_json_string( pRoot );
			json_object_put( pRoot );
			m_ddi.Publish( "", "rpc_reporter_remote_search_queue", strEvent );
			//if( szSQLQuery )
			//	CoTaskMemFree( szSQLQuery );
			return;
		}
		//if( szSQLQuery )
		{

			//CAtlArray< SearchRow > aRows;
			//Load names

			json_object *pFields = json_object_object_get( pObj, "fields" );
			int nLen = json_object_array_length( pFields );
			CAtlArray<CStringA> aCols;
			for( int i = 0; i < nLen; i++ )
			{
				json_object *pUser = json_object_array_get_idx( pFields, i );
				aCols.Add( json_object_get_string( pUser ) );
			}


			CAutoCS acs( m_csUsers );
			//SearchRow row;
			CAtlArray<CStringA> aValues;
			for( size_t nUser = 0; nUser <= m_aUsers.GetCount(); nUser++ )
			{
				if( nUser < m_aUsers.GetCount() && m_aUsers[ nUser ]->GetToken() )
					m_aUsers[ nUser ]->GetToken()->Impersonate();

				CDataSource cDataSource;
				cDataSource.OpenFromInitializationString( L"provider=Search.CollatorDSO.1;EXTENDED PROPERTIES=\"Application=Windows\"" );

				CSession cSession;
				hr = cSession.Open( cDataSource );
				CCommand<CDynamicAccessor, CRowset> cCommand;
				hr = cCommand.Open( cSession, strSQL );
				CStringA strCvt;
				if( SUCCEEDED(hr) )
				{
					json_object *pResults = json_object_new_array();
					for( hr = cCommand.MoveFirst(); S_OK == hr; hr = cCommand.MoveNext() )
					{
						aValues.RemoveAll();
						for( DBORDINAL i = 1; i <= cCommand.GetColumnCount(); i++ )
						{
							DBSTATUS status;
							DBORDINAL nCol = i;
							cCommand.GetStatus( nCol, &status );
							if( status == DBSTATUS_S_OK || status == DBSTATUS_S_TRUNCATED )
							{
								DBTYPE type;
								cCommand.GetColumnType( nCol, &type);
								if( type == DBTYPE_VARIANT || type == DBTYPE_WSTR )
								{
									CString strValue;
									if( type == DBTYPE_VARIANT )
									{
										CComVariant var = *static_cast<VARIANT *>(cCommand.GetValue(nCol));
										var.ChangeType( VT_BSTR );
										strValue = var.bstrVal;
									}
									else
										strValue = reinterpret_cast<WCHAR*>(cCommand.GetValue(nCol));
									if( i == 1 )
									{
										if( strValue.Find( _T('$') ) != -1 )
										{
											CComVariant varName = *static_cast<VARIANT *>(cCommand.GetValue(2));
											varName.ChangeType( VT_BSTR );
											NormalizePath( strValue, varName.bstrVal );
										}
									}
									CW2A strVal( strValue, CP_UTF8 );
									aValues.Add( strVal );
								}
								else if( type == VT_DATE )
								{
									SYSTEMTIME st;
									DATE dDate = *static_cast<DATE*>(cCommand.GetValue(nCol));
									if( VariantTimeToSystemTime( dDate, &st ) )
									{
										CStringA strValue;
										FormatDateTime( st, strValue );
										aValues.Add( strValue );
									}

								}
								else
								{
									switch( type )
									{
									case VT_I4:
										{
											int32_t nValue = *static_cast<int32_t*>(cCommand.GetValue(nCol));
											strCvt.Format( "%I32d", nValue );
											aValues.Add( strCvt );
										}
										break;
									case VT_UI4:
										{
											uint32_t nValue = *static_cast<uint32_t*>(cCommand.GetValue(nCol));
											strCvt.Format( "%I32u", nValue );
											aValues.Add( strCvt );
										}
										break;
									case VT_I8:
										{
											int64_t nValue = *static_cast<int64_t*>(cCommand.GetValue(nCol));
											strCvt.Format( "%I64d", nValue );
											aValues.Add( strCvt );
										}
										break;
									case VT_UI8:
										{
											uint64_t nValue = *static_cast<uint64_t*>(cCommand.GetValue(nCol));
											strCvt.Format( "%I64u", nValue );
											aValues.Add( strCvt );
										}
										break;
									default:
										aValues.Add( "BAD TYPE" );
									}
								}
							}
							else
								aValues.Add( "BAD STATUS" );

						}//for i
						//InsertRow( aRows, row );
						InsertRow( pResults, szKeyword, aCols, aValues );

						//aRows.Add( row );
					}
					{
						CString strValue;
						json_object *pRoot = json_object_new_object();
						json_object *pResponse = json_object_new_object();

						json_object_object_add( pResponse, "query", json_object_new_string(szID) );
						json_object_object_add( pResponse, "command", json_object_new_string("search") );
						if( m_strDDI_LIC.GetLength() )
							json_object_object_add( pResponse, "license", json_object_new_string( m_strDDI_LIC ) );
						else
							json_object_object_add( pResponse, "license", json_object_new_string("") );
						AddEventInfo( pResponse, true );

						json_object_object_add( pResponse, "ip", json_object_new_string( m_strIP ) );
						json_object_object_add( pResponse, "machine", json_object_new_string( m_strMachine ) );
						CStringA strUserA;
						if( nUser < m_aUsers.GetCount() )
							strUserA = m_aUsers[ nUser ]->m_strUserName;
						else
							strUserA = _T("SYSTEM");
						json_object_object_add( pResponse, "user", json_object_new_string( strUserA ) );

						const char * aNames[] = { "", "path", "name", "modified", "type", "context", "coincidence" };

						if( m_strWifiLocations.GetLength() )
						{
							json_object *oGeoData = json_tokener_parse( m_strWifiLocations );
							if( oGeoData )
								json_object_object_add( pResponse, "geodata", oGeoData );
						}

						json_object_object_add( pResponse, "resultset", pResults );
						json_object_object_add( pResponse, "code", json_object_new_int( 0 ) );
						json_object_object_add( pRoot, "response", pResponse );

						CStringA strEvent = json_object_to_json_string( pRoot );
						json_object_put( pRoot );
						m_ddi.Publish( "", "rpc_reporter_remote_search_queue", strEvent );
					}


				}

				if( nUser < m_aUsers.GetCount() && m_aUsers[ nUser ]->GetToken() )
					m_aUsers[ nUser ]->GetToken()->Revert();
			}

			//Generate json

			//if( aRows.GetCount() )

			//CoTaskMemFree( szSQLQuery );
		}
	}


	void DoGeoData( const char *szID )
	{
		if( m_strWifiLocations.GetLength() )
		{
			json_object *pRoot = json_object_new_object();
			json_object *pResponse = json_object_new_object();

			json_object_object_add( pResponse, "query", json_object_new_string(szID) );
			json_object_object_add( pResponse, "command", json_object_new_string("geodata") );
			if( m_strDDI_LIC.GetLength() )
				json_object_object_add( pResponse, "license", json_object_new_string( m_strDDI_LIC ) );
			else
				json_object_object_add( pResponse, "license", json_object_new_string("") );
			AddEventInfo( pResponse, true );

			json_object_object_add( pResponse, "ip", json_object_new_string( m_strIP ) );
			json_object_object_add( pResponse, "machine", json_object_new_string( m_strMachine ) );

			json_object *oGeoData = json_tokener_parse( m_strWifiLocations );
			if( oGeoData )
				json_object_object_add( pResponse, "geodata", oGeoData );

			json_object_object_add( pRoot, "response", pResponse );

			CStringA strEvent = json_object_to_json_string( pRoot );
			json_object_put( pRoot );
			m_ddi.Publish( "", "rpc_reporter_remote_search_queue", strEvent );
		}
	}

	void DoMessage( const CStringA &strMsg )
	{
	}

	void AddGroup( json_object *pObj )
	{
		if( pObj )
		{
	        json_object *pGroup = json_object_object_get( pObj, "group" );
			if( pGroup )
			{
				const char *szGroup = json_object_get_string( pGroup );
				json_object *pUsers = json_object_object_get( pObj ,"users" );
				if( json_object_get_type( pUsers ) == json_type_array )
				{
					int nLen = json_object_array_length( pUsers );
					CAtlList<CString> lstUsers;
					CString strUser;
					for( int i = 0; i < nLen; i++ )
					{
						json_object *pUser = json_object_array_get_idx( pUsers, i );
						strUser = json_object_get_string( pUser );
						DwUnEscapeUrl( strUser );
						lstUsers.AddTail( strUser );
					}

					//bool bSubscribe = false;
					{
						CAutoCS acs(m_csUsers);
						CStringA strUserNameA;
						for( size_t i = 0; i < m_aUsers.GetCount(); i++ )
						{
							if( lstUsers.Find( m_aUsers[ i ]->m_strUserName ) )
							{
								m_aUsers[ i ]->AddGroup( szGroup );
								strUserNameA = m_aUsers[ i ]->m_strUserName;
								m_ddi.SubscribeUserToGroup( strUserNameA, szGroup, m_aUsers[ i ] );
								//bSubscribe = true;
							}
						}
					}
					//if( bSubscribe )
					//	m_ddi.SubscribeGroup( szGroup );
				}
			}
		}
	}

	void DeleteGroup( json_object *pObj )
	{
		json_object *pGroup = json_object_object_get( pObj, "group" );
		const char *szGroup = json_object_get_string( pGroup );
		
		if( szGroup )
		{
			json_object *pUser = json_object_object_get( pObj, "user" );

			if( json_object_get_type( pUser ) == json_type_array )
			{
				int nLen = json_object_array_length( pUser );
				if( !nLen )
				{
					CAutoCS acs(m_csUsers);
					for( size_t i = 0; i < m_aUsers.GetCount(); i++ )
						m_aUsers[ i ]->DeleteGroup( szGroup );
				}
				else
				{
					CString strUser;
					for( int i = 0; i < nLen; i++ )
					{
						json_object *pExt = json_object_array_get_idx( pUser, i );
						strUser = json_object_get_string( pExt );
						DwUnEscapeUrl( strUser );
						CAutoCS acs(m_csUsers);
						for( size_t j = 0; j < m_aUsers.GetCount(); j++ )
						{
							if( strUser == m_aUsers[ j ]->m_strUserName )
								m_aUsers[ j ]->DeleteGroup( szGroup );
						}
					}
				}
			}
			else
			{
				const char *szUser = json_object_get_string( pUser );
				if( !szUser || !lstrlenA( szUser ) ) //erase group for all users
				{
					CAutoCS acs(m_csUsers);
					for( size_t i = 0; i < m_aUsers.GetCount(); i++ )
						m_aUsers[ i ]->DeleteGroup( szGroup );
				}
				else
				{
					CAutoCS acs(m_csUsers);
					CString strUser;
					strUser = szUser;
					DwUnEscapeUrl( strUser );
					for( size_t i = 0; i < m_aUsers.GetCount(); i++ )
					{
						if( m_aUsers[ i ]->m_strUserName == strUser )
						{
							m_aUsers[ i ]->DeleteGroup( szGroup );
							break;
						}
					}
				}
			}
		}
	}

	void CvtToBinary( CAtlArray<BYTE> &aBuffer, CStringA &str )
	{
		int nCount = 0;
		BYTE nAdd = 0;
		for( int i = 0; i < str.GetLength(); i++ )
		{
			bool bNum = str[ i ] >= '0' && str[ i ] <= '9';
			bool bMay = str[ i ] >= 'A' && str[ i ] <= 'F';
			bool bMin = str[ i ] >= 'a' && str[ i ] <= 'f';

			if( bNum || bMay || bMin )
			{
				BYTE nNum;
				if( bNum )
					nNum = str[ i ] - '0';
				else if( bMay )
					nNum = str[ i ] - 'A' + 10;
				else
					nNum = str[ i ] - 'a' + 10;

				if( nCount % 2 )
				{
					nAdd |= nNum;
					aBuffer.Add( nAdd );
				}
				else
				{
					nAdd = nNum << 4;
				}
				++nCount;
			}
		}
	}

	void AddHeapLockApp( HeapLockApp &hlp )
	{
		CRegKey rKeyHeapLocker;
		if( !GetRegKey( _T("SOFTWARE\\Drainware\\SecurityEndpoint\\Sandbox"), rKeyHeapLocker ) )
			return;

		CRegKey rKeyApps;
		if( !GetRegKey( _T("SOFTWARE\\Drainware\\SecurityEndpoint\\Sandbox\\Applications"), rKeyApps ) )
			return;

		CRegKey rKeyApp;
		CString strKey = _T("SOFTWARE\\Drainware\\SecurityEndpoint\\Sandbox\\Applications\\");
		strKey += hlp.m_strName;

		if( !GetRegKey( strKey, rKeyApp ) )
			return;

		rKeyApp.SetDWORDValue( _T("NOPSledLengthMin"), hlp.m_dwNOPSledLengthMin );
		rKeyApp.SetDWORDValue( _T("PrivateUsageMax"), hlp.m_dwPrivateUsageMax );
		rKeyApp.SetDWORDValue( _T("GenericPreAllocate"), hlp.m_dwGenericPreAllocate );

		if( hlp.m_strSearchString.GetLength() )
		{
			CAtlArray<BYTE> aBuffer;
			CvtToBinary( aBuffer, hlp.m_strSearchString );
			rKeyApp.SetBinaryValue( _T("SearchString"), aBuffer.GetData(), ULONG(aBuffer.GetCount()) );
			//rKeyApp.SetBinaryValue( _T("SearchString"), hlp.m_strSearchString.GetBuffer(), hlp.m_strSearchString.GetLength() * sizeof(WCHAR) );
		}
		else
			rKeyApp.DeleteValue( _T("SearchString") );

		rKeyApp.SetDWORDValue( _T("SearchMode"), hlp.m_dwSearchMode );
		rKeyApp.SetDWORDValue( _T("NullPagePreallocate"), hlp.m_dwNullPagePreallocate );
		rKeyApp.SetDWORDValue( _T("Verbose"), hlp.m_dwVerbose );
		rKeyApp.SetDWORDValue( _T("util.printf"), hlp.m_dwutil_printf );
		rKeyApp.SetDWORDValue( _T("ForceTermination"), hlp.m_dwResumeMonitoring );
		rKeyApp.SetDWORDValue( _T("ResumeMonitoring"), hlp.m_dwResumeMonitoring );

		strKey += _T("\\");
		strKey += _T("Addresses");

		CRegKey rKeyAddress;

		if( !GetRegKey( strKey, rKeyAddress ) )
			return;
		rKeyAddress.SetDWORDValue( _T("util.printf"), hlp.m_dwutil_printf );
	}

	void UpdateSearchIndex()
	{
		//Sleep( 20000 );
		PWSTR szSQLQuery = NULL;
		CComPtr<ISearchManager> pSearchManager;
		HRESULT hr = CoCreateInstance(__uuidof(CSearchManager), NULL, CLSCTX_LOCAL_SERVER, IID_PPV_ARGS(&pSearchManager));

		if( hr != S_OK )
		{
			//Send event error
			return;
		}

        CComPtr<ISearchCatalogManager> pSearchCatalogManager;
        hr = pSearchManager->GetCatalog( L"SystemIndex", &pSearchCatalogManager );//TODO: Search into trash
		if( SUCCEEDED( hr ) )
		{
			CComPtr<ISearchCrawlScopeManager> pCrawl;
			hr = pSearchCatalogManager->GetCrawlScopeManager( &pCrawl );
			if( SUCCEEDED( hr ) && pCrawl )
			{
				BOOL bIncluded = FALSE;
				//if( SHGetSpecialFolderPath( NULL, szPath, CSIDL_BITBUCKET, FALSE ) )
				//{
				//	pCrawl->IncludedInCrawlScope( szPath, &bIncluded );
				//	if( !bIncluded )
				//		pCrawl->AddUserScopeRule( szPath, TRUE, TRUE, 0 );
				//}
				TCHAR nDrive = _T('A');
				TCHAR szDrive[ 8 ] = _T("X:\\");
				TCHAR szRecycle[] = _T("X:\\$Recycle.Bin");
				DWORD dwMask = GetLogicalDrives();
				DWORD dwUnit = 1;
				for( int i = 0; i < 32; i++ )
				//for( int i = 0; i < 4; i++ )
				{
					if( dwUnit & dwMask )
					{
						szDrive[ 0 ] = nDrive;
						if( GetDriveType( szDrive ) == DRIVE_FIXED )
						{
							TCHAR szDevice[] = _T("file:///C:\\*");
							szDevice[ 8 ] = nDrive;
							pCrawl->IncludedInCrawlScope( szDevice, &bIncluded );
							if( !bIncluded )
								hr = pCrawl->AddUserScopeRule( szDevice, TRUE, TRUE, 0 );

							//TCHAR szRecycleBin[] = _T("file:///C:\\$Recycle.Bin");
							//szRecycleBin[ 8 ] = nDrive;
							//pCrawl->IncludedInCrawlScope( szRecycleBin, &bIncluded );
							//if( !bIncluded )
							//	hr = pCrawl->AddUserScopeRule( szRecycleBin, TRUE, TRUE, 0 );

							szRecycle[ 0 ] = nDrive;
							if( PathIsDirectory( szRecycle ) )
							{
								CString strFolder;
								CString strUserDir = szRecycle;
								strUserDir += _T("\\*");
								WIN32_FIND_DATA fd = { 0 };
								HANDLE hFind = FindFirstFile( strUserDir, &fd );

								if( hFind != INVALID_HANDLE_VALUE )
								{
									do
									{
										if( lstrcmp( fd.cFileName, _T(".") ) && lstrcmp( fd.cFileName, _T("..") ) )
										{
											strFolder = szRecycle; strFolder += _T("\\");
											strFolder += fd.cFileName;
											if( PathIsDirectory( strFolder ) )
											{
												strFolder.Insert( 0, _T("file:///") );
												strFolder += _T("\\");
												hr = pCrawl->IncludedInCrawlScope( strFolder, &bIncluded );
												if( !bIncluded )
													hr = pCrawl->AddUserScopeRule( strFolder, TRUE, TRUE, 0 );
											}
										}
									}while( FindNextFile( hFind, &fd ) );
									FindClose( hFind );
								}
							}
						}
					}
					++nDrive;
					dwUnit <<= 1;
				}

				hr = pCrawl->SaveAll();
				hr = S_OK;
			}
		}
	}

	void NormalizePath( CString &strPath, const WCHAR *szName )
	{
		CString str = strPath;
		str.MakeUpper();
		if( str.Find( _T("$RECYCLE.BIN") ) == -1 )
			return;

		int nPos = strPath.Find( _T('\\'), 4 ); // Skip X:\a
		if( nPos != -1 )
		{
			str.SetString( strPath, nPos + 1 ); //Include last '\' character

			CString strFolder;
			CString strUserDir = str;
			strUserDir += _T("*");
			WIN32_FIND_DATA fd = { 0 };
			HANDLE hFind = FindFirstFile( strUserDir, &fd );

			if( hFind != INVALID_HANDLE_VALUE )
			{
				do
				{
					strFolder = str;
					if( lstrcmp( fd.cFileName, _T(".") ) && lstrcmp( fd.cFileName, _T("..") ) )
					{
						strFolder += fd.cFileName;
						strFolder += _T('\\');
						strFolder += szName;
						if( FileExist( strFolder ) )
						{
							strPath = strFolder;
							FindClose( hFind );
							return;
						}
					}
				}while( FindNextFile( hFind, &fd ) );
				FindClose( hFind );
			}
		}
	}

	void UninstallPrinterMonitor()
	{

		//bool bMonitorInUse = false;

		//if( !::DeleteMonitor( NULL, NULL, DWM_NAME ) )
		//	bMonitorInUse = GetLastError() == ERROR_PRINT_MONITOR_IN_USE;
		//Sleep( 1000 * 50 );
		//if( bMonitorInUse )
		{
			CEvent evt;
			evt.Create( NULL, FALSE, FALSE, _T("DrainwarePrintMonitorEvtOff") );
			if( evt )
				evt.Set();
			::Sleep( 100 );
			WaitForSingleObject( evt, 5000 );
			//Sleep( 500 ); //give some time to monitor to stop itself and resotre old ports
		}

		DWORD dwFlags = PRINTER_ENUM_LOCAL;// | PRINTER_ENUM_NETWORK | PRINTER_ENUM_REMOTE;
		//DWORD dwFlags = PRINTER_ENUM_LOCAL | PRINTER_ENUM_NETWORK | PRINTER_ENUM_REMOTE;
		DWORD dwNeeded = 0, dwReturned = 0;
		EnumPrinters( dwFlags, NULL, 2, NULL, 0, &dwNeeded, &dwReturned );
		if( !dwNeeded )
			return;
		PBYTE pBuffer = new BYTE[ dwNeeded ];
		if( !EnumPrinters( dwFlags, NULL, 2, pBuffer, dwNeeded, &dwNeeded, &dwReturned ) )
		{
			delete [] pBuffer;
			return;
		}

		PRINTER_INFO_2 *pPrinterInfo = reinterpret_cast<PRINTER_INFO_2 *>(pBuffer);
		for( DWORD i = 0; i < dwReturned; i++ )
		{
			HANDLE hPrinter;
			PRINTER_DEFAULTS pd = { 0 };
			pd.DesiredAccess = PRINTER_ALL_ACCESS;

			if( !lstrcmp( pPrinterInfo[ i ].pPortName, _T("DwPort:") ) && OpenPrinter( pPrinterInfo[ i ].pPrinterName, &hPrinter, &pd ) )
			{
				TCHAR szPortName[ 512 ] = { 0 };
				DWORD dwType = REG_SZ;
				DWORD dwSize = 512;
				DWORD dwError = GetPrinterDataEx( hPrinter, _T("Drainware"), _T("DwOldPort"), &dwSize, (PBYTE)szPortName, 512, &dwSize );
				if( ERROR_SUCCESS == dwError )
				{
					pPrinterInfo[ i ].pPortName = szPortName;
					SetPrinter( hPrinter, 2, reinterpret_cast<LPBYTE>(&pPrinterInfo[ i ]), 0 );
				}
				else
				{
					pPrinterInfo[ i ].pPortName = _T("");
					CString strPrinter = pPrinterInfo[ i ].pPrinterName;
					strPrinter.MakeUpper();
					if( strPrinter.Find( _T("FAX") ) != -1 )
					{
						pPrinterInfo[ i ].pPortName = _T("SHRFAX:");
					}
					else if( strPrinter.Find( _T("XPS") ) != -1 )
					{
						pPrinterInfo[ i ].pPortName = _T("XPSPort:");
					}
					SetPrinter( hPrinter, 2, reinterpret_cast<LPBYTE>(&pPrinterInfo[ i ]), 0 );
				}
				ClosePrinter( hPrinter );
			}
		}
		delete [] pBuffer;

		//::DeleteMonitor( NULL, NULL, DWM_NAME );

		//if( bMonitorInUse ) //Last try to delete monitor correctelly
		//::DeleteMonitor( NULL, NULL, DWM_NAME );
		HANDLE hThread = ::CreateThread( NULL, 0, ThreadDeleteMonitor, reinterpret_cast<PVOID>(this), 0, NULL );
		//WaitForSingleObject( hThread, 5000 );
		if( WaitForSingleObject( hThread, 5000 ) == WAIT_TIMEOUT ) //Wait 5 sec else DeleteMonitor is hangedup
		{
			::TerminateThread( hThread, 0 );
			::CloseHandle( hThread );
			RestartSpooler();
			//Try one more time
			hThread = ::CreateThread( NULL, 0, ThreadDeleteMonitor, reinterpret_cast<PVOID>(this), 0, NULL );
			WaitForSingleObject( hThread, 5000 );
		}
		::CloseHandle( hThread );
	}

	static DWORD WINAPI ThreadDeleteMonitor( LPVOID pVoid )
	{
		::DeleteMonitor( NULL, NULL, DWM_NAME );
		return 0;
	}

	void DeleteMonitor() //remove manually from registry due to a blocker DeleteMonitor API function
	{

	}

	//void InitCrypt()
	//{
	//	HRSRC hRsrc = FindResource( NULL, _T("public.pem"), _T("DRAINWARE") );
	//	if( hRsrc )
	//	{
	//		HGLOBAL hGlobal = LoadResource( NULL, hRsrc );
	//		if( hGlobal )
	//		{
	//			char *pKey = (char*)LockResource( hGlobal );
	//			DWORD dwSize = SizeofResource( NULL, hRsrc );
	//			std::vector<char> vKey( dwSize );
	//			CopyMemory( &vKey.front(), pKey, dwSize );
	//			g_crypt.ImportPublicKey( vKey );
	//		}
	//	}

	//	hRsrc = FindResource( NULL, _T("server.key"), _T("DRAINWARE") );
	//	if( hRsrc )
	//	{
	//		HGLOBAL hGlobal = LoadResource( NULL, hRsrc );
	//		if( hGlobal )
	//		{
	//			char *pKey = (char*)LockResource( hGlobal );
	//			DWORD dwSize = SizeofResource( NULL, hRsrc );
	//			std::vector<char> vKey( dwSize );
	//			CopyMemory( &vKey.front(), pKey, dwSize );
	//			g_crypt.ImportPrivateKey( vKey );
	//		}
	//	}
	//}

	void RestartSpooler()
	{
		SC_HANDLE hSCM = ::OpenSCManager( NULL, NULL, SC_MANAGER_ALL_ACCESS );
		if( hSCM )
		{
			SC_HANDLE hService = OpenService( hSCM, _T("SPOOLER"), SERVICE_ALL_ACCESS );
			if( hService )
			{
				SERVICE_STATUS ss;
				ControlService( hService, SERVICE_CONTROL_STOP, &ss );

				SERVICE_STATUS_PROCESS ssp;
				DWORD dwNeeded;
				int nRetries = 0;
				while( nRetries++ < 100 )
				{
					if( !QueryServiceStatusEx( hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(SERVICE_STATUS_PROCESS), &dwNeeded ) )
						break;
					if( ssp.dwCurrentState == SERVICE_STOPPED )
						break;
					Sleep( 100 );
				}

				StartService( hService, 0, NULL );

				CloseServiceHandle( hService );
			}
			CloseServiceHandle( hSCM );
		}
	}

	void PingAmqp()
	{
		CAutoCS acs(m_csUsers);
		for( size_t i = 0; i < m_aUsers.GetCount(); i++ )
		{

			json_object *pRoot = json_object_new_object();
			json_object *pResponse = json_object_new_object();

			json_object_object_add( pResponse, "query", json_object_new_string("") );
			json_object_object_add( pResponse, "command", json_object_new_string("ping") );
			if( m_strDDI_LIC.GetLength() )
				json_object_object_add( pResponse, "license", json_object_new_string( m_strDDI_LIC ) );
			else
				json_object_object_add( pResponse, "license", json_object_new_string("") );
			AddEventInfo( pResponse, true );

			json_object_object_add( pResponse, "ip", json_object_new_string( m_strIP ) );
			json_object_object_add( pResponse, "machine", json_object_new_string( m_strMachine ) );

			json_object_object_add( pRoot, "response", pResponse );

			CStringA strEvent = json_object_to_json_string( pRoot );
			json_object_put( pRoot );
			m_ddi.Publish( "", "rpc_reporter_remote_search_queue", strEvent );
		}
	}

	CDDI m_ddi;
	//CComObject<CDwService> *m_pDwService;
	CAtlArray< CDwService * > m_aClients;
	CAtlArray< CUserData * > m_aUsers;
	CAtlArray< CString > m_lstAtpProcs;

	CCriticalSection m_csClients;
	CCriticalSection m_csUsers;
	CCriticalSection m_csOffline;

	DWORD m_dwLoadAppInit;
	CStringA m_strDDI_IP;
	int m_nDDIPort;
	CStringA m_strDDI_LIC;
	CStringA m_strMachine;
	CStringA m_strIP;
	CString m_strOfflineEvents; //Path to file that contain events
	CStringA m_strWifiLocations; 
	bool m_bPendingEvents;
	CEvent m_evtUpdate;
	//CFileFollower m_fileFollower;
	HANDLE m_hThreadPrinter;
	bool m_bClosing;
	CEvent m_evtPrintMonitor;

	//RemoteFiles
	CAtlArray< RemoteFile > m_aRemoteFiles;
	HANDLE m_hThreadRemoteFiles;
	HANDLE m_hThreadDDI;
	HANDLE m_hThreadUpdate;
	HANDLE m_hThreadFS;
	CCriticalSection m_csRemoteFiles;
	DWORD m_dwEnableFS;
	bool m_bOnShutdown;
	bool m_bReloadPolicies;
	VARIANT_BOOL m_bUpdate;
	CString m_strProxy;
	DWORD m_bProxyEnable;
	CAtlArray< CString > m_aProxy;
};

CDrainwareSecurityAgentModule _AtlModule;

ISecurityAgent  *g_pSecurityAgent = &_AtlModule;


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
	//Sleep( 10000 );
	return _AtlModule.WinMain(nShowCmd);
}

