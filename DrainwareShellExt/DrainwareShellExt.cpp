// DrainwareShellExt.cpp : Implementation of DLL Exports.


#include "stdafx.h"
#include "resource.h"
#include "dllmain.h"
#include <vector>
#include <ShlObj.h>
#include <Shlwapi.h>
#include "Helper.h"
#include "WaitForCheck.h"

#include "../../DrainwareLibs/sqlite3/sqlite3.h"
//#include "../DwLib/DwLib.h"
extern bool GetModuleDirectory( CString &strPath );
extern bool FileExist( LPCTSTR szFileName );
extern bool GetTempPath( CString &strPath );
extern bool IsMappedDrive( PCTSTR szOrg, CString &strUNCPath );

// Used to determine whether the DLL can be unloaded by OLE.
STDAPI DllCanUnloadNow(void)
{
			return _AtlModule.DllCanUnloadNow();
}

// Returns a class factory to create an object of the requested type.
STDAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, LPVOID* ppv)
{
		return _AtlModule.DllGetClassObject(rclsid, riid, ppv);
}

// DllRegisterServer - Adds entries to the system registry.
STDAPI DllRegisterServer(void)
{
	// registers object, typelib and all interfaces in typelib
	HRESULT hr = _AtlModule.DllRegisterServer( FALSE );
		return hr;
}

// DllUnregisterServer - Removes entries from the system registry.
STDAPI DllUnregisterServer(void)
{
	HRESULT hr = _AtlModule.DllUnregisterServer( FALSE );
		return hr;
}

// DllInstall - Adds/Removes entries to the system registry per user per machine.
STDAPI DllInstall(BOOL bInstall, LPCWSTR pszCmdLine)
{
	HRESULT hr = E_FAIL;
	static const wchar_t szUserSwitch[] = L"user";

	if (pszCmdLine != NULL)
	{
		if (_wcsnicmp(pszCmdLine, szUserSwitch, _countof(szUserSwitch)) == 0)
		{
			ATL::AtlSetPerUserRegistration(true);
		}
	}

	if (bInstall)
	{	
		hr = DllRegisterServer();
		if (FAILED(hr))
		{
			DllUnregisterServer();
		}
	}
	else
	{
		hr = DllUnregisterServer();
	}

	return hr;
}


// DrainwareShellExt.cpp : Implementation of CDrainwareShellExt

#include "stdafx.h"
#include "..\DrainwareSecurityAgent\DrainwareSecurityAgent_i.h"
#include "..\DrainwareSecurityAgent\DrainwareSecurityAgent_i.c"
#include "DrainwareShellExt.h"


// CDrainwareShellExt

//#ifndef _M_X64
const CLSID CLSID_DrainwareShellExt = { 0x6933ea63, 0x28b6, 0x42d2, { 0x84, 0x57, 0x28, 0x62, 0xfc, 0xf2, 0x2f, 0xd3 } };
//#else
//const CLSID CLSID_DrainwareShellExt = { 0xbd8c9514, 0xbbb1, 0x4dba, { 0xad, 0x9d, 0xb1, 0x33, 0xd5, 0xf9, 0x72, 0x66 } };
//#endif

static bool LoadFile( const CString &strFile, CStringA &strContent )
{
	bool bRet = false;
	strContent.Empty();
	CAtlFile f;
	if( f.Create( strFile, GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING ) == S_OK )
	{
		ULONGLONG nLen = 0;
		if( S_OK == f.GetSize( nLen ) && nLen > 0 )
		{
			char *pBuffer = new char[ DWORD(nLen) + 1 ];
			DWORD nBytesRead = 0;
			if( S_OK == f.Read( pBuffer, DWORD(nLen), nBytesRead ) )
			{
				pBuffer[ nBytesRead ] = 0;
				strContent = pBuffer;
				bRet = true;
			}
		}
	}
	return bRet;
}

static bool IsDirectory( PCTSTR szPath )
{
	DWORD dwAttr;
	if( ( dwAttr = ::GetFileAttributes( szPath ) ) != INVALID_FILE_ATTRIBUTES )
	{
		if( dwAttr & FILE_ATTRIBUTE_DIRECTORY )
			return true;
	}
	return false;
}

static bool IsDirectoryA( PCSTR szPath )
{
	DWORD dwAttr;
	if( ( dwAttr = ::GetFileAttributesA( szPath ) ) != INVALID_FILE_ATTRIBUTES )
	{
		if( dwAttr & FILE_ATTRIBUTE_DIRECTORY )
			return true;
	}
	return false;
}

static bool IsDrive( LPCTSTR szDrive )
{
	TCHAR nDrive = szDrive[ 0 ];
	return ( ( nDrive >= _T('A') && nDrive <= _T('Z') ) || ( nDrive >= _T('a') && nDrive <= _T('z') ) ) && szDrive[ 1 ] == _T(':');
}

DWORD WINAPI CDrainwareShellExt::ThreadDlg( PVOID pVoid )
{
	CWaitForCheck dlgWait;
	dlgWait.DoModal( GetActiveWindow() );
	return 0;
}

int CDrainwareShellExt::SQLiteCallback( void *pUserData, int argc, char **argv, char **azColName )
{
	CDrainwareShellExt *pThis = reinterpret_cast<CDrainwareShellExt *>(pUserData);
	for( int i = 0; i < argc; i++ )
	{
		if( IsDirectoryA( argv[ i ] ) )
		{
			CString strDir;
			strDir = argv[ i ];
			if( strDir.Find( _T("\\\\?\\") ) != -1 )
				strDir.Delete( 0, 4 );
			strDir.MakeUpper();
			//pThis->m_aNetPaths.Add( strDir );
			pThis->m_aGDrivePaths.Add( strDir );
			//MessageBox( GetActiveWindow(), strDir, _T("GoogleDir"), 0 );
		}
	}
	return 0;
}

CDrainwareShellExt::CDrainwareShellExt()
{
	TCHAR szAppData[ MAX_PATH ];
	PIDLIST_ABSOLUTE pidl;
	::SHGetSpecialFolderLocation( NULL, CSIDL_APPDATA, &pidl );
	::SHGetPathFromIDList( pidl, szAppData );
	if( pidl )
		CoTaskMemFree( pidl );

	CString strFile = szAppData;
	strFile += _T("\\Dropbox\\host.db");

	CStringA strContent;

	if( LoadFile( strFile, strContent ) )
	{
		BYTE szPath[ MAX_PATH ];
		CStringA strLine;
		int nPos = 0;
		int nLen;
		while( true )
		{
			nPos = strContent.Find( '\n' );
			if( nPos != -1 )
			{
				strLine = strContent.Left( nPos );
				strContent.Delete(0, nPos + 1 );
			}
			else
				strLine = strContent;
			nLen = MAX_PATH;
			if( Base64Decode( strLine, strLine.GetLength(), szPath, &nLen ) )
			{
				szPath[ nLen ] = 0;
				CString strDir;
				strDir = ( const char*)szPath;
				strDir.MakeUpper();
				if( IsDirectory( strDir ) )
				{
					//m_aNetPaths.Add( strDir );
					m_aDropBoxPaths.Add( strDir );
					//::MessageBox( GetActiveWindow(), strDir, _T("Added Directory"), 0 );
				}
			}
			if( nPos == -1 )
				break;
		}
	}

	::SHGetSpecialFolderLocation( NULL, CSIDL_LOCAL_APPDATA, &pidl );
	::SHGetPathFromIDList( pidl, szAppData );
	if( pidl )
		CoTaskMemFree( pidl );

	CStringA strFileA;
	strFileA = szAppData;
	strFileA += "\\Google\\Drive\\sync_config.db";

	sqlite3 *pDB;

	if( sqlite3_open( strFileA, &pDB ) == SQLITE_OK )
	{
		char *zErrMsg = 0;
		if( sqlite3_exec( pDB, "SELECT data_value FROM data WHERE entry_key='local_sync_root_path'", SQLiteCallback, this, &zErrMsg ) != SQLITE_OK )
			sqlite3_free( zErrMsg );
	}

	sqlite3_close( pDB );

	CRegKey rKey;
	//HeapLocker32.dll
	if( ERROR_SUCCESS == rKey.Open( HKEY_CURRENT_USER, _T("SOFTWARE\\Microsoft\\SkyDrive"), KEY_READ | KEY_WRITE ) )
	{
		TCHAR szValue[ MAX_PATH * 2 ];
		ULONG nSize = MAX_PATH * 2;
		if( ERROR_SUCCESS == rKey.QueryStringValue( _T("UserFolder"), szValue, &nSize ) )
		{
			CString strDir = szValue;
			strDir.MakeUpper();
			m_aSkyDrivePaths.Add( strDir );
		}
	}
	//::MessageBox( GetActiveWindow(), szAppData, _T("Local AppData"), 0 );
}


bool CDrainwareShellExt::IsUSB( LPCTSTR pszDrive )
{
	if( !IsDrive( pszDrive ) )
		return false;
	TCHAR nDrive = pszDrive[ 0 ];
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

static void CreateDropFiles( CAtlArray<CString> &aFiles, STGMEDIUM &stg, DROPFILES *pDropSrc )
{
	size_t nDropFilesSize = sizeof(DROPFILES) + sizeof(TCHAR);

	for( size_t i = 0; i < aFiles.GetCount(); i++ )
	{
		nDropFilesSize += aFiles[ i ].GetLength() * sizeof(TCHAR) + sizeof(TCHAR);
	}

	HGLOBAL hGlobal = GlobalAlloc( GHND, nDropFilesSize );
	PBYTE pMem = reinterpret_cast<PBYTE>(GlobalLock( hGlobal ));
	DROPFILES *pDrop = reinterpret_cast<DROPFILES*>(pMem);
	pDrop->pFiles = sizeof( DROPFILES);
	pDrop->fNC = pDropSrc->fNC;
	pDrop->fWide = sizeof(TCHAR) > 1 ? TRUE : FALSE;
	pDrop->pt = pDropSrc->pt;

	PTSTR pFiles = reinterpret_cast<PTSTR>(pMem + sizeof(DROPFILES));

	for( size_t i = 0; i < aFiles.GetCount(); i++ )
	{
		lstrcat( pFiles, aFiles[ i ] );
		pFiles += aFiles[ i ].GetLength() + 1;
	}

	GlobalUnlock( hGlobal );
	stg.tymed = TYMED_HGLOBAL;
	stg.hGlobal = hGlobal;
	stg.pUnkForRelease = NULL;
}

static void CreateShellIdList( std::vector< std::vector<BYTE> > &aItems, STGMEDIUM &stg )
{
	size_t nOffset = sizeof(UINT) * aItems.size() + sizeof(UINT);
	size_t nTotalSize = nOffset;
	for( size_t i = 0; i < aItems.size(); i++ )
		nTotalSize += aItems[ i ].size();

	HGLOBAL hGlobal = GlobalAlloc( GHND, nTotalSize );
	PBYTE pMem = reinterpret_cast<PBYTE>(GlobalLock( hGlobal ));
	LPIDA pIDA = reinterpret_cast<LPIDA>(pMem);

	pIDA->cidl = UINT(aItems.size());

	
	for( UINT i = 0; i < pIDA->cidl; i++ )
	{
		pIDA->aoffset[ i ] = UINT(nOffset);
		CopyMemory( pMem + nOffset, &aItems[ i ][ 0 ], aItems[ i ].size() );
		nOffset += aItems[ i ].size();
	}

	pIDA->cidl--;

	GlobalUnlock( hGlobal );
	stg.tymed = TYMED_HGLOBAL;
	stg.hGlobal = hGlobal;
	stg.pUnkForRelease = NULL;

}
static size_t ItemSize( LPITEMIDLIST pidItem )
{
	size_t nSize = 0;

	while( pidItem->mkid.cb )
	{
		nSize = pidItem->mkid.cb;
		pidItem = reinterpret_cast<LPITEMIDLIST>(reinterpret_cast<PBYTE>(pidItem) + pidItem->mkid.cb);
	}

	nSize += 2;

	return nSize;
}

//static void AddItem( std::vector< std::vector<BYTE> > &aItems, LPITEMIDLIST pidItem )
//{
//	BYTE *pMem = reinterpret_cast<BYTE *>(pidItem);
//	size_t nItemSize = ItemSize( pidItem );
//	std::vector<BYTE> shItem( pMem, pMem + nItemSize );
//	aItems.push_back( shItem );
//}
//
//static bool AddItem( IDwEndPoint *pEndPoint, PCTSTR szPath, PCTSTR szDestDir, std::vector< std::vector<BYTE> > &aItems, LPITEMIDLIST pidlAbsParent, LPITEMIDLIST pidlRelParent, LPITEMIDLIST pidlChild, IShellFolder *pParentFolder )
//{
//	bool bBlocked = false;
//	if( !PathIsDirectory( szPath ) )
//	//if(true)
//	{
//		//VARIANT_BOOL bCheck;
//		CComBSTR bstrFile = szPath;
//
//		//pEndPoint->CheckFile( bstrFile, &bCheck );
//		//if( bCheck == VARIANT_TRUE )
//		//	AddItem( aItems, pIDA, (pIDA)->aoffset[ i + 1 ] );
//		CString strPath = szPath;
//		if( strPath.Find( _T(".7z") ) == -1 )
//		{
//			LPITEMIDLIST pidlRelChildFolder = NULL;
//		
//			pidlRelChildFolder = ::ILCombine( pidlRelParent, pidlChild );
//
//			AddItem( aItems, pidlRelChildFolder );
//
//			::ILFree( pidlRelChildFolder );
//
//			CString strOrg = szPath;
//			CString strDest = szDestDir;
//			int nFind = strOrg.ReverseFind( _T('\\') );
//			strDest.Append( strOrg.GetBuffer() + nFind + 1 );
//
//			CComBSTR bstrFileDest = strDest;
//			pEndPoint->SkipFile( bstrFileDest );
//		}
//		else
//			bBlocked = true;
//	}
//	else
//	{
//		CComPtr<IShellFolder> pFolder;
//		pParentFolder->BindToObject( pidlChild, NULL, IID_IShellFolder, (void**)&pFolder );
//
//		if( !pFolder )
//			return false;
//
//		CComPtr<IEnumIDList> pEnum;
//		pFolder->EnumObjects( NULL, SHCONTF_FOLDERS | SHCONTF_NONFOLDERS | SHCONTF_INCLUDEHIDDEN, &pEnum );
//
//		if( !pEnum )
//			return false;
//
//		pEnum->Reset();
//		LPITEMIDLIST pidlFile = NULL;
//		ULONG nFetch = 0;
//		bool bChildFolderBlocked = false;
//		LPITEMIDLIST pidlFullChildFolder = ::ILCombine( pidlAbsParent, pidlChild );
//		LPITEMIDLIST pidlRelChildFolder = NULL;
//		
//		if( pidlRelParent )
//			pidlRelChildFolder = ::ILCombine( pidlRelParent, pidlChild );
//
//		CString strOrg = szPath;
//		CString strDest = szDestDir;
//		int nFind = strOrg.ReverseFind( _T('\\') );
//		strDest.Append( strOrg.GetBuffer() + nFind + 1 );
//		strDest.Append( _T("\\") );
//
//
//		while( S_OK == pEnum->Next( 1, &pidlFile, &nFetch ) )
//		{
//			TCHAR szPathChild[ 1024 ] = { 0 };
//			//LPITEMIDLIST pChild = (LPITEMIDLIST)(((LPBYTE)pIDA)+(pIDA)->aoffset[i+1]);
//			
//			LPITEMIDLIST pidlFullChild = ::ILCombine( pidlFullChildFolder, pidlFile );
//			LPITEMIDLIST pidlRelChild = ::ILCombine( pidlRelChildFolder, pidlFile );
//			::SHGetPathFromIDList( pidlFullChild, szPathChild );
//
//			if( AddItem( pEndPoint, szPathChild, strDest, aItems, pidlFullChild, pidlRelChild, pidlFile, pFolder ) )
//				bChildFolderBlocked = true;
//
//			::ILFree( pidlFullChild );
//			::ILFree( pidlRelChild );
//		}
//
//		::ILFree( pidlFullChildFolder );
//		if( pidlRelChildFolder )
//			::ILFree( pidlRelChildFolder );
//
//		if( !bChildFolderBlocked )
//			AddItem( aItems, pidlChild );
//		else 
//			bBlocked = true;
//	}
//
//	return bBlocked;
//}

static bool CheckItem( FILE_TYPE nFileType, IDwService *pService, PCTSTR szDestDir, LPITEMIDLIST pidlAbsParent, LPITEMIDLIST pidlChild, IShellFolder *pParentFolder, bool bExternFolder )
{
	if( CWaitForCheck::m_bCancel )
		return false;
	TCHAR szPath[ 1024 ];

	LPITEMIDLIST pItem= ::ILCombine( pidlAbsParent, pidlChild );
	::SHGetPathFromIDList( pItem, szPath );
	::ILFree( pItem );


	CString strOrg = szPath;
	CString strDest = szDestDir;

	if( strDest.GetLength() && strDest[ strDest.GetLength() - 1 ] != _T('\\') )
		strDest += _T('\\');

	int nFind = strOrg.ReverseFind( _T('\\') );
	strDest.Append( strOrg.GetBuffer() + nFind + 1 );


	if( !PathIsDirectory( szPath ) )
	{
		CComBSTR bstrFileDest = strDest;
		if( szDestDir[ 0 ] == szPath[ 0 ] && IsDrive( szDestDir ) && !bExternFolder ) //Same drive, don't check, skip
		{
			if( CDrainwareShellExt::IsUSB( szPath ) )
				pService->SkipFile( bstrFileDest );
		}
		else
		{
			if( !(szPath[ 0 ] == _T('\\') && szPath[ 1 ] == _T('\\') ) )
			{
				CComBSTR bstrFile = szPath;
				VARIANT_BOOL bDeleteFile;
				pService->CheckFile( nFileType, bstrFile, bstrFileDest, bExternFolder ? VARIANT_TRUE : VARIANT_FALSE, &bDeleteFile );
				if( bDeleteFile == VARIANT_TRUE )
					return false;
			}
			else //Check if it is remote unit
			{
				CComBSTR bstrFile = szPath;
				VARIANT_BOOL bDeleteFile = VARIANT_FALSE;
				pService->CheckRemoteUnit( bstrFile, bstrFileDest, bExternFolder ? VARIANT_TRUE : VARIANT_FALSE, &bDeleteFile );
				if( bDeleteFile == VARIANT_TRUE )
					return false;
			}
			//CString strOutput = _T("CheckFile: ");
			//strOutput += bstrFileDest;
			//strOutput += _T("\n");
			//::OutputDebugString( strOutput );
		}
	}
	else
	{
		CComPtr<IShellFolder> pFolder;
		pParentFolder->BindToObject( pidlChild, NULL, IID_IShellFolder, (void**)&pFolder );

		if( !pFolder )
			return true;

		CComPtr<IEnumIDList> pEnum;
		pFolder->EnumObjects( NULL, SHCONTF_FOLDERS | SHCONTF_NONFOLDERS | SHCONTF_INCLUDEHIDDEN, &pEnum );

		if( !pEnum )
			return true;

		pEnum->Reset();
		LPITEMIDLIST pidlFile = NULL;
		ULONG nFetch = 0;
		//bool bChildFolderBlocked = false;
		LPITEMIDLIST pidlFullChildFolder = ::ILCombine( pidlAbsParent, pidlChild );

		strDest.Append( _T("\\") );
		bool bRet = true;
		while( bRet && S_OK == pEnum->Next( 1, &pidlFile, &nFetch ) )
		{
			if( CWaitForCheck::m_bCancel || !CheckItem( nFileType, pService, strDest, pidlFullChildFolder, pidlFile, pFolder, bExternFolder ) )
				bRet = false;
			CoTaskMemFree( pidlFile );
		}

		::ILFree( pidlFullChildFolder );
		return bRet;
	}
	if( CWaitForCheck::m_bCancel )
		return false;
	return true;
}

ULONG CDrainwareShellExt::IsInetFolder( LPCTSTR szFolder )
{
	if( ( szFolder[ 0 ] == '\\' && szFolder[ 1 ] == '\\' ) )
		return FT_NETWORK_DEVICE;

	CString strUNCPath;
	if( IsMappedDrive( szFolder, strUNCPath ) )
		return FT_NETWORK_DEVICE;

	CString strFolder = szFolder;
	strFolder.MakeUpper();
	if( strFolder.GetLength() && strFolder[ strFolder.GetLength() - 1 ] == _T('\\') )
		strFolder.Truncate( strFolder.GetLength() - 1 );

	for( size_t i = 0; i < m_aGDrivePaths.GetCount(); i++ )
	{
		if( strFolder.Find( m_aGDrivePaths[ i ] ) != -1 )
			return FT_GOOGLE_DRIVE;
		//if( m_aGDrivePaths[ i ].Find( strFolder ) != -1 )
		//	return FT_GOOGLE_DRIVE;
	}

	for( size_t i = 0; i < m_aDropBoxPaths.GetCount(); i++ )
	{
		if( strFolder.Find( m_aDropBoxPaths[ i ] ) != -1 )
			return FT_DROPBOX_DRIVE;
		//if( m_aDropBoxPaths[ i ].Find( strFolder ) != -1 )
		//	return FT_DROPBOX_DRIVE;
	}

	for( size_t i = 0; i < m_aSkyDrivePaths.GetCount(); i++ )
	{
		if( strFolder.Find( m_aSkyDrivePaths[ i ] ) != -1 )
			return FT_SKY_DRIVE;
		//if( m_aSkyDrivePaths[ i ].Find( strFolder ) != -1 )
		//	return FT_SKY_DRIVE;
	}

	return 0;
}

static void TestDataObject( IDataObject *pDataObject )
{
	CComPtr<IEnumFORMATETC> pEnumFmtc;
	pDataObject->EnumFormatEtc( DATADIR_GET, &pEnumFmtc );
	if( pEnumFmtc )
	{
		pEnumFmtc->Reset();
		FORMATETC etc;
		HRESULT hr;
		TCHAR szName[ 256 ];
		while( ( hr = pEnumFmtc->Next( 1, &etc, NULL ) ) == S_OK )
		{
			if( GetClipboardFormatName( etc.cfFormat, szName, 256 ) )
			{
				CString strFmt;
				strFmt.Format( _T("Clipboard Format: %s\n"), szName );
				::OutputDebugString( strFmt );
			}
		}
	}
}

static void ClearDataObject( IDataObject *pDataObject )
{
	UINT idFileNameA = RegisterClipboardFormat( CFSTR_FILENAMEA );
	FORMATETC etc = { idFileNameA, NULL, DVASPECT_CONTENT, -1, TYMED_HGLOBAL };

	CStgMedium stg;
	HRESULT hr = pDataObject->GetData( &etc, &stg );
	LPVOID pDst = GlobalLock( stg.hGlobal );
	SecureZeroMemory( pDst, GlobalSize( stg.hGlobal ) );
	GlobalUnlock( stg.hGlobal );
	hr = pDataObject->SetData( &etc, &stg, TRUE );

	etc.cfFormat = RegisterClipboardFormat( CFSTR_FILENAMEW );
	hr = pDataObject->GetData( &etc, &stg );
	pDst = GlobalLock( stg.hGlobal );
	SecureZeroMemory( pDst, GlobalSize( stg.hGlobal ) );
	GlobalUnlock( stg.hGlobal );
	hr = pDataObject->SetData( &etc, &stg, TRUE );

	etc.cfFormat = CF_HDROP;
	hr = pDataObject->GetData( &etc, &stg );
	pDst = GlobalLock( stg.hGlobal );
	SecureZeroMemory( PBYTE(pDst) + sizeof(DROPFILES), GlobalSize( stg.hGlobal ) - sizeof(DROPFILES) );
	CString strDir;
	GetTempPath( strDir );
	strDir += _T("message_from_drainware.txt");
	CAtlFile f;
	f.Create( strDir, GENERIC_WRITE, FILE_SHARE_READ, CREATE_ALWAYS );
	CStringA strMsg = "The organization's policy doesn't allow to move/copy sensitive information to an external storage";
	if( f )
	{
		f.Write( strMsg, strMsg.GetLength() );
		f.Close();
	}
	if( FileExist( strDir ) )
	{
		SIZE_T nSize = sizeof(DROPFILES) + sizeof(TCHAR) * strDir.GetLength() + sizeof(TCHAR) * 2;
		HGLOBAL hGlobal = GlobalAlloc( GPTR, nSize );
		if( hGlobal )
		{
			PBYTE pBuffer = (PBYTE)GlobalLock( hGlobal );
			DROPFILES *pDropFiles = (DROPFILES *)pBuffer;
			*pDropFiles = *(DROPFILES *)pDst;
			pDropFiles->pFiles = sizeof( DROPFILES );
			CopyMemory( pBuffer + sizeof(DROPFILES), strDir.GetBuffer(), strDir.GetLength() * sizeof(TCHAR) );
			pDropFiles->fWide = sizeof(TCHAR) == 2 ? TRUE : FALSE;
			GlobalUnlock( stg.hGlobal );
			ReleaseStgMedium( &stg );
			stg.hGlobal = hGlobal;
			stg.tymed = TYMED_HGLOBAL;
		}
	}
	GlobalUnlock( stg.hGlobal );
	hr = pDataObject->SetData( &etc, &stg, TRUE );

	hr = S_OK;
}

STDMETHODIMP CDrainwareShellExt::Initialize( LPCITEMIDLIST pidlFolder, LPDATAOBJECT pDataObject, HKEY hProgID )
{
	//MessageBox( GetActiveWindow(), _T("CDrainwareShellExt::Initialize"), _T("DrainwareShellExt"), 0 );
	//::OutputDebugString(  _T("CDrainwareShellExt::Initialize\n") );
	TCHAR szDestDir[ MAX_PATH ];
	szDestDir[ 0 ] = 0;
	if( !::SHGetPathFromIDList( pidlFolder, szDestDir ) )
		return E_FAIL;

	ULONG bNetFolder = IsInetFolder( szDestDir );
	bool bIsUSB = IsUSB( szDestDir );
	bool bExternFolder = bIsUSB || bNetFolder;
	//if( bExternFolder ) commented because of remote files( to add rads )
	{
		CComPtr<IDwService> pService;
		//HRESULT hr = CoGetClassObject( IID_IDwEndPoint, CLSCTX_LOCAL_SERVER, NULL, IID_IDwEndPoint, (void**)&pEndPoint );
		HRESULT hr = pService.CoCreateInstance( CLSID_DwService, NULL, CLSCTX_LOCAL_SERVER );
		if( pService )
		{
			ULONG pt;
			pService->GetProtectionType( &pt );

			if( !( pt & PROTECT_PENDRIVE ) && bIsUSB )
				return S_OK;

			if( !( pt & PROTECT_NETWORKDEVICE_DST ) && bNetFolder == FT_NETWORK_DEVICE )
				return S_OK;

			if( !( pt & PROTECT_GOOGLEDRIVE ) && bNetFolder == FT_GOOGLE_DRIVE )
				return S_OK;

			if( !( pt & PROTECT_DROPBOX ) && bNetFolder == FT_DROPBOX_DRIVE )
				return S_OK;

			if( !( pt & PROTECT_SKYDRIVE ) && bNetFolder == FT_SKY_DRIVE )
				return S_OK;


			UINT idShellIDList = RegisterClipboardFormat( CFSTR_SHELLIDLIST );

			FORMATETC etc = { idShellIDList, NULL, DVASPECT_CONTENT, -1, TYMED_HGLOBAL };
			CStgMedium stg;
			
			if( FAILED( pDataObject->GetData( &etc, &stg ) ) )
				return E_INVALIDARG;

			bool bEraseDataObject = false;
			LPIDA pIDA = reinterpret_cast<LPIDA>(GlobalLock( stg.hGlobal ));
			if( !pIDA )
				return E_INVALIDARG;

			LPITEMIDLIST pidlParentFolder = (LPITEMIDLIST)(((LPBYTE)pIDA)+(pIDA)->aoffset[0]);

			bool bRemoveADS = false, bCheckForRemote = false;
			if( bExternFolder )
			{
			//std::vector< std::vector<BYTE> > aItems;
				CComPtr<IShellFolder> pDesktopFolder;
				CComPtr<IShellFolder> pParentFolder;
				SHGetDesktopFolder( &pDesktopFolder );

				if( !pDesktopFolder )
					return E_FAIL;

				HRESULT hr = pDesktopFolder->BindToObject( pidlParentFolder, NULL, IID_IShellFolder, (void**)&pParentFolder );

				//if( !pParentFolder )
				//	return E_FAIL;

				HANDLE hThread = CreateThread( NULL, 0, ThreadDlg, PVOID(this), 0, NULL );
				FILE_TYPE nFileType = TYPE_FILE_NONE;
				if( bIsUSB )
					nFileType = TYPE_PENDRIVE;
				else
				{
					switch( bNetFolder )
					{
					case FT_NETWORK_DEVICE:
						nFileType = TYPE_NETWORK_DEVICE;
					break;
					case FT_GOOGLE_DRIVE:
						nFileType = TYPE_GOOGLE_DRIVE;
					break;
					case FT_DROPBOX_DRIVE:
						nFileType = TYPE_DROPBOX;
					break;
					case FT_SKY_DRIVE:
						nFileType = TYPE_SKY_DRIVE;
					break;
					}
				}

				for( UINT i = 0; i < pIDA->cidl; i++ )
				{
					LPITEMIDLIST pChild = (LPITEMIDLIST)(((LPBYTE)pIDA)+(pIDA)->aoffset[i+1]);
					if( CWaitForCheck::m_bCancel || !CheckItem( nFileType, pService, szDestDir, pidlParentFolder, pChild, pParentFolder ? pParentFolder : pDesktopFolder, bExternFolder ) )
					{
						bEraseDataObject = true;
						break;
					}
				}

				if( bEraseDataObject )
				{
					OSVERSIONINFO osvi = { 0 };
					osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
					GetVersionEx( &osvi );
					if( osvi.dwMajorVersion < 6 ) //XP
						ClearDataObject( pDataObject );
					CStgMedium stgClear;
					stgClear.tymed = TYMED_HGLOBAL;
					SIZE_T nStgSize = GlobalSize( stg.hGlobal );
					stgClear.hGlobal = GlobalAlloc( GPTR, nStgSize );
					LPVOID pDst = GlobalLock( stgClear.hGlobal );
					SecureZeroMemory( pDst, nStgSize );
					CopyMemory( pDst, pIDA, sizeof(CIDA)  );
					LPIDA pDstIDA = reinterpret_cast<LPIDA>(pDst);
					pDstIDA->cidl = 0;
					GlobalUnlock( stgClear.hGlobal );
					GlobalUnlock( stg.hGlobal );

					HRESULT hr = pDataObject->SetData( &etc, &stgClear, TRUE );
					hr = 0;
					OleSetClipboard( NULL );
					OpenClipboard( NULL );
					EmptyClipboard();
					CloseClipboard();
					//ReleaseStgMedium( &stgClear );
				}
				else
					bRemoveADS = true;

				CWaitForCheck::m_bStop = true;
				if( WaitForSingleObject( hThread, 2000 ) == WAIT_TIMEOUT )
				{
					TerminateThread( hThread, 0 );
				}
				CloseHandle( hThread );
			}//bExternFolder
			else
			{
				TCHAR szPathOrg[ MAX_PATH ];
				::SHGetPathFromIDList( pidlParentFolder, szPathOrg );
				bCheckForRemote = IsInetFolder( szPathOrg ) ? true : false;
			}

			if( bCheckForRemote || bRemoveADS )
			{
				CComBSTR bstrDest = szDestDir;
				for( UINT i = 0; i < pIDA->cidl; i++ )
				{
					LPITEMIDLIST pChild = (LPITEMIDLIST)(((LPBYTE)pIDA)+(pIDA)->aoffset[i+1]);
					TCHAR szPath[ 1024 ];

					LPITEMIDLIST pItem= ::ILCombine( pidlParentFolder, pChild );
					::SHGetPathFromIDList( pItem, szPath );
					::ILFree( pItem );
					CString strPath = szPath;
					while( strPath.Replace( _T(".\\"), _T("\\") ) );
					CComBSTR bstrFile = strPath;
					if( bRemoveADS )
						pService->RemoveADS( bstrFile );
					else
						pService->AddIfRemoteFile( bstrDest, bstrFile );
				}
				if( bCheckForRemote )
					pService->AddIfRemoteFile( NULL, NULL );
			}

			if( !bEraseDataObject )
				GlobalUnlock( stg.hGlobal );
			ReleaseStgMedium( &stg );
		}
	}

	return S_OK;
}

STDMETHODIMP CDrainwareShellExt::QueryContextMenu(HMENU hmenu,UINT uMenuIndex,UINT uidFirstCmd,UINT uidLastCmd,UINT uFlags)
{
 //   if (uFlags & CMF_DEFAULTONLY)
 //       return MAKE_HRESULT(SEVERITY_SUCCESS,FACILITY_NULL,0);

	//MessageBox( GetActiveWindow(), _T("CDrainwareShellExt::QueryContextMenu"), _T("DrainwareShellExt"), 0 );
 //   return MAKE_HRESULT( SEVERITY_SUCCESS, FACILITY_NULL, 2 );
	return S_OK;
}

STDMETHODIMP CDrainwareShellExt::InvokeCommand( LPCMINVOKECOMMANDINFO pInfo )
{
	//MessageBox( GetActiveWindow(), _T("CDrainwareShellExt::InvokeCommand"), _T("DrainwareShellExt"), 0 );
	return S_OK;
}


//UINT CDrainwareShellExt::CopyCallback( HWND hwnd, UINT wFunc, UINT wFlags, PCTSTR pszSrcFile, DWORD dwSrcAttribs, LPCTSTR pszDestFile, DWORD dwDestAttribs )
//{
//	if( ( wFunc == FO_COPY || wFunc == FO_MOVE ) && !( dwSrcAttribs & FILE_ATTRIBUTE_DIRECTORY ) )
//	{
//
//		CComPtr<IDwService> pService;
//		//HRESULT hr = CoGetClassObject( IID_IDwEndPoint, CLSCTX_LOCAL_SERVER, NULL, IID_IDwEndPoint, (void**)&pEndPoint );
//		HRESULT hr = pService.CoCreateInstance( CLSID_DwService, NULL, CLSCTX_LOCAL_SERVER );
//		if( !pService )
//			return IDYES;
//
//		ULONG bNetFolder = IsInetFolder( pszDestFile );
//		bool bIsUSB = IsUSB( pszDestFile );
//		bool bExternFolder = bIsUSB || bNetFolder;
//
//		FILE_TYPE nFileType = TYPE_FILE_NONE;
//		if( bIsUSB )
//			nFileType = TYPE_PENDRIVE;
//		else
//		{
//			switch( bNetFolder )
//			{
//			case FT_NETWORK_DEVICE:
//				nFileType = TYPE_NETWORK_DEVICE;
//			break;
//			case FT_GOOGLE_DRIVE:
//				nFileType = TYPE_GOOGLE_DRIVE;
//			break;
//			case FT_DROPBOX_DRIVE:
//				nFileType = TYPE_DROPBOX;
//			break;
//			case FT_SKY_DRIVE:
//				nFileType = TYPE_SKY_DRIVE;
//			break;
//			}
//		}
//
//
//		CComBSTR bstrFileDest = pszDestFile;
//
//		if( pszDestFile[ 0 ] == pszSrcFile[ 0 ] && IsDrive( pszDestFile ) && !bExternFolder ) //Same drive, don't check, skip
//		{
//			if( CDrainwareShellExt::IsUSB( pszSrcFile ) )
//				pService->SkipFile( bstrFileDest );
//		}
//		else
//		{
//			if( !(pszSrcFile[ 0 ] == _T('\\') && pszSrcFile[ 1 ] == _T('\\') ) )
//			{
//				CComBSTR bstrFile = pszSrcFile;
//				VARIANT_BOOL bDeleteFile;
//				pService->CheckFile( nFileType, bstrFile, bstrFileDest, bExternFolder ? VARIANT_TRUE : VARIANT_FALSE, &bDeleteFile );
//				if( bDeleteFile == VARIANT_TRUE )
//					return IDNO;
//			}
//			else //Check if it is remote unit
//			{
//				CComBSTR bstrFile = pszSrcFile;
//				VARIANT_BOOL bDeleteFile = VARIANT_FALSE;
//				pService->CheckRemoteUnit( bstrFile, bstrFileDest, bExternFolder ? VARIANT_TRUE : VARIANT_FALSE, &bDeleteFile );
//				if( bDeleteFile == VARIANT_TRUE )
//					return IDNO;
//			}
//		}
//	}
//	return IDYES;
//}