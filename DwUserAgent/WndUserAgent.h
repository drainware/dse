#pragma once

#include "resource.h"
#include "SrvMngr.h"
#include "ITrayWindow.h"
#include "KeyLogger.h"
#include "TrayWindow.h"

#include "..\DwLib\Crc32.h"

class CWndUserAgent : public ATL::CWindowImpl< CWndUserAgent >,
	public CComObjectRoot,
	//public CComObjectRootEx<CComObjectThreadModel>,
	public _IDwServiceEvents,
	public ITrayWindow,
	public IDriveNotify
{
public:
	CWndUserAgent();
	~CWndUserAgent();

	BEGIN_COM_MAP(CWndUserAgent)
		COM_INTERFACE_ENTRY(_IDwServiceEvents)
	END_COM_MAP()


	BEGIN_MSG_MAP(CMyWindow)
	   MESSAGE_HANDLER( WM_CREATE, OnCreate )
	   MESSAGE_HANDLER( WM_DESTROY, OnDestroy )
	   MESSAGE_HANDLER( WM_CHANGECBCHAIN, OnChangeCBChain )
	   MESSAGE_HANDLER( WM_DRAWCLIPBOARD, OnDrawClipboard )
	   MESSAGE_HANDLER( WM_DEVICECHANGE, OnDeviceChange )
	END_MSG_MAP()


	LRESULT OnCreate( UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL& bHandled );
	LRESULT OnDestroy( UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL& bHandled );
	LRESULT OnChangeCBChain( UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL& bHandled );
	LRESULT OnDrawClipboard( UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL& bHandled );
	LRESULT OnDeviceChange( UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL& bHandled );

//_IDwServiceEvents
	HRESULT WINAPI OnClose( VARIANT_BOOL bUpdate );
	HRESULT WINAPI OnShowTrayWindow( ULONG nMsgType, VARIANT_BOOL *bShowed );
	HRESULT WINAPI OnGetScreenShot( VARIANT_BOOL *bShowed );
	HRESULT WINAPI OnShowCheckDialog( ULONG nMsgType, VARIANT_BOOL *bShowed );
	HRESULT WINAPI OnShowUserMessage( BSTR bstrMsg );
	HRESULT WINAPI OnActiveModules( ULONG nActiveModules );
//IDriveNotify
	void OnDeviceSafeRemoval( TCHAR nDrive );
//ITrayWindow
	void ShowMessage( UINT nType );

private:

	static DWORD WINAPI ThreadOCR( PVOID pVoid );
	static DWORD WINAPI ThreadDlg( PVOID pVoid );
	static DWORD WINAPI ThreadProxy( PVOID pVoid );
	void LoadProxyInfo( CString &str, DWORD &nEnable );
	bool DownloadFile( const CString &strUrl, CStringA &str );
	void CheckForProxy();
	bool CheckForUpdates();
	void CheckClipboard();
	void CheckOCR();
	void CheckBitmap( HBITMAP hBitmap, int cx, int cy );
	static bool IsUSB( TCHAR nDrive );
	void LoadUsbWatchers();
	void UnloadUsbWatchers();
	void ReleaseService();
	void RemoveDrive( TCHAR nDrive );
	void GetJpegStream( HBITMAP hBmp, PBYTE &pBuffer, size_t &nSize );
	void GetScreenShot( PBYTE &pBuffer, size_t &nSize );
	void CloseCheckDlg();
	void UpdateModuleConfig( ULONG pt );
	void RegisterDrive( TCHAR nDrive, HANDLE hDevice );

	struct DevNotify
	{
		//HANDLE hDevice;
		TCHAR nDrive;
		HDEVNOTIFY hDevNotify;
		DevNotify( TCHAR nD, HDEVNOTIFY hN ) : nDrive( nD ), hDevNotify( hN )
		{}
	};

	HWND m_hWndNextCBViewer;
	DWORD m_dwCookie;
	CSimpleArray< CDriveWatcher * > m_aDrives;
	CString m_strBmp;
	CString m_strProxy;
	CKeyLogger m_kl;
	CTrayWindow m_wndTray;
	CLSID m_clsidJpeg;
	HANDLE m_thCheck;
	HANDLE m_thProxy;
	ULONG m_nCheckType;
	HDEVNOTIFY m_hDevNotify;
	ULONG m_pt;
	bool m_bInitialized;
	//CAtlArray<DevNotify> m_aDevices;
	CAtlMap<HDEVNOTIFY,TCHAR> m_mapNotifies;
	static Crc32 m_crc32;

	DWORD m_crcDrainware;
	DWORD m_crcCurrent;
	volatile HBITMAP m_hBmpCopy;
	CAtlMap< DWORD, bool > m_mapCRC;
	CCriticalSection m_csOCR;
	CEvent m_evtOCR;
	volatile bool m_bCheckingOCR;
	CCriticalSection m_csClipboard;
	CSrvMngr m_SrvMngr;
	CEvent m_evtProxy;
};
