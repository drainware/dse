#include "StdAfx.h"
#include "DriveWatcher.h"
#include <stdint.h>
#include "resource.h"

HANDLE LoadDrive( LPCTSTR szDrive )
{
	return CreateFile( szDrive, FILE_LIST_DIRECTORY, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 
	FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED, NULL );
}

bool IsFile( LPCTSTR szFileName )
{
	DWORD dwAttr = GetFileAttributes( szFileName );
	if( GetFileAttributes( szFileName ) == INVALID_FILE_ATTRIBUTES )
		return false;

	if( dwAttr & ( FILE_ATTRIBUTE_DEVICE | FILE_ATTRIBUTE_DIRECTORY ) )
		return false;

	return true;
}

CDriveWatcher::CDriveWatcher( TCHAR nDrive, CSrvMngr *pService, IDriveNotify *pNotify ) : m_hThread( INVALID_HANDLE_VALUE ), m_pNotify( pNotify )
{
	m_nDrive = nDrive;
	m_pService = pService;
	m_evt.Create( NULL, FALSE, FALSE, NULL );
	//m_hChangeNotify = FindFirstChangeNotification( szDrive, TRUE, FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_LAST_WRITE );
	ZeroMemory( m_Buffer, m_nBufferSize );
	m_hThread = CreateThread( NULL, 0, ThreadWatch, reinterpret_cast<PVOID>(this),  0, NULL );
}

CDriveWatcher::~CDriveWatcher(void)
{
	//if( m_hChangeNotify != INVALID_HANDLE_VALUE )
	//	FindCloseChangeNotification( m_hChangeNotify );
	//if( m_hDirectory )
	//	CloseHandle( m_hDirectory ), m_hDirectory = INVALID_HANDLE_VALUE;
	//if( m_th != INVALID_HANDLE_VALUE )
	//{
	//	WaitForSingleObject( m_th, INFINITE );
	//	CloseHandle( m_th );
	//}
}


DWORD WINAPI CDriveWatcher::ThreadWatch( PVOID pVoid )
{
	CDriveWatcher *pThis = reinterpret_cast<CDriveWatcher*>(pVoid);
	CoInitializeEx( NULL, COINIT_MULTITHREADED );
	pThis->DoWatch();
	CoUninitialize();
	return 0;
}

void CDriveWatcher::DoWatch()
{
	TCHAR szDrive[ 4 ] = _T("X:\\");
	szDrive[ 0 ] = m_nDrive;
	ZeroMemory( &m_ov, sizeof(OVERLAPPED) );
	m_ov.hEvent = this;
	HANDLE hDirectory = LoadDrive( szDrive );

	bool bSafeRemoval = false;

	while( true )
	{
		BOOL bRet = ReadDirectoryChangesW( hDirectory, m_Buffer, m_nBufferSize, TRUE, FILE_NOTIFY_CHANGE_LAST_WRITE, NULL, 
			&m_ov, DriveChanged );

		//if( !bRet )
		//{
		//	//CString strError;
		//	//strError.Format( _T("ReadDirectoryChangesW Failed! - Error %d"), dwError );
		//	//MessageBox( GetActiveWindow(), strError, _T("Error"), MB_ICONSTOP );
		//}
		DWORD dwError = GetLastError();
		bSafeRemoval = dwError == ERROR_ACCESS_DENIED || dwError == ERROR_INVALID_HANDLE;
		if( bSafeRemoval )
			break;

		if( WAIT_IO_COMPLETION != WaitForSingleObjectEx( m_evt, INFINITE, TRUE ) )
			break;
	}
	if( hDirectory != INVALID_HANDLE_VALUE )
		CloseHandle( hDirectory );
	if( bSafeRemoval && m_pNotify )
		m_pNotify->OnDeviceSafeRemoval( m_nDrive );
}


void CDriveWatcher::Destroy()
{
	if( m_hThread != INVALID_HANDLE_VALUE )
	{
		m_evt.Set();
		WaitForSingleObjectEx( m_hThread, INFINITE, TRUE );
		CloseHandle( m_hThread );
	}
}

VOID CALLBACK CDriveWatcher::DriveChanged( DWORD dwErrorCode, DWORD dwNumberOfBytesTransfered, LPOVERLAPPED lpOverlapped )
{
	if( lpOverlapped )
	{
		CDriveWatcher *pThis = reinterpret_cast<CDriveWatcher *>(lpOverlapped->hEvent);
		if( pThis && dwNumberOfBytesTransfered )
		{
			pThis->m_Buffer[ dwNumberOfBytesTransfered ] = 0;
			pThis->OnDirChanged();
		}
	}
}

void CDriveWatcher::OnDirChanged()
{
	//MessageBox( GetActiveWindow(), _T("OnDirChanged()"), _T("Info"), MB_ICONINFORMATION );
	FILE_NOTIFY_INFORMATION *pNotify = reinterpret_cast<FILE_NOTIFY_INFORMATION *>(m_Buffer);
	while( true )
	{
		if( pNotify->Action == FILE_ACTION_MODIFIED )
		{
			//CheckFile
			WCHAR szName[ MAX_PATH * 2 ];
			CopyMemory( szName, pNotify->FileName, pNotify->FileNameLength * sizeof(WCHAR) );
			szName[ pNotify->FileNameLength ] = 0;
			CString strFilePath = _T("X:\\");
			strFilePath.SetAt( 0, m_nDrive );
			strFilePath += szName;
			//MessageBox( GetActiveWindow(), strFilePath, _T("CheckFile"), MB_ICONINFORMATION );

			if( IsFile( strFilePath ) && m_pService )
			{
				VARIANT_BOOL bDelete = VARIANT_FALSE;
				HRESULT hr = m_pService->CheckFile( NULL, CComBSTR( strFilePath ), VARIANT_FALSE, &bDelete );
				if( bDelete == VARIANT_TRUE )
				{
					while( !DeleteFile( strFilePath ) )
						::Sleep( 50 );
				}
			}
				//CheckFile( strFilePath );
			//if( CheckFile( szName ) )
			//{
			//	DeleteFile( szName );
			//	CString strMsg, strInformation;
			//	strMsg.LoadString( IDS_FILE_DELETED );
			//	strInformation.LoadString( IDS_INFORMATION );
			//	MessageBox( GetActiveWindow(), strMsg, strInformation, MB_OK );
			//}
			//Call to check file
			//MessageBox( GetActiveWindow(), szName, _T("USB File"), 0 );
		}
		if( !pNotify->NextEntryOffset )
			break;
		pNotify = reinterpret_cast<FILE_NOTIFY_INFORMATION *>(reinterpret_cast<PBYTE>(pNotify) + pNotify->NextEntryOffset);
	}
}

//bool CDriveWatcher::CheckFile( PCTSTR szFileName )
//{
//	return g_UserData.CheckFile( szFileName );
//}
