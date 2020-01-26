#pragma once

HANDLE LoadDrive( LPCTSTR szDrive );

#include "SrvMngr.h"
#include "IDriveNotify.h"

class CDriveWatcher
{
public:
	CDriveWatcher( TCHAR nDrive, CSrvMngr *pService, IDriveNotify *pNotify = NULL );
	~CDriveWatcher(void);
	static DWORD WINAPI ThreadWatch( PVOID pVoid );
	void DoWatch();
	void Destroy();

	//ATL::CString m_strDrive;
	TCHAR m_nDrive;
private:
	//HANDLE m_hChangeNotify;
	//bool CheckFile( PCTSTR szFileName );
	void OnDirChanged();
	static VOID CALLBACK DriveChanged( DWORD dwErrorCode, DWORD dwNumberOfBytesTransfered, LPOVERLAPPED lpOverlapped );
	//void HashToString( BYTE *aDigest, int nLen, CStringA &str );
	static const int m_nBufferSize = 1024 * 32;
	__declspec(align(32)) BYTE m_Buffer[ m_nBufferSize ];
	HANDLE m_hThread;
	CEvent m_evt;
	__declspec(align(32)) OVERLAPPED m_ov;
	CSrvMngr *m_pService;
	IDriveNotify *m_pNotify;
};

