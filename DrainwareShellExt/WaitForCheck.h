// WaitForCheck.h: declaración de CWaitForCheck

#pragma once

#include "resource.h"       // Símbolos principales

#include <atlhost.h>
#include <atltypes.h>

using namespace ATL;

#include <GdiPlus.h>
#pragma comment( lib, "gdiplus" )

#pragma comment(lib, "Msimg32.lib")
// CWaitForCheck

extern HINSTANCE g_hInst;

static bool LoadPng( LPCTSTR pName, LPCTSTR pType, Gdiplus::Bitmap *&pBitmap  )
{
	HMODULE hInst = g_hInst;
    HRSRC hResource = ::FindResource( hInst, pName, pType );
    if( !hResource )
        return false;
    
    DWORD imageSize = ::SizeofResource( hInst, hResource );
    if( !imageSize )
        return false;

    const void* pResourceData = ::LockResource( ::LoadResource( hInst, hResource ) );
    if( !pResourceData )
        return false;

    HGLOBAL hBuffer = ::GlobalAlloc( GMEM_MOVEABLE, imageSize );
    if( hBuffer )
    {
        void* pBuffer = ::GlobalLock( hBuffer );
		if (pBuffer)
		{
			CopyMemory(pBuffer, pResourceData, imageSize);

			IStream* pStream = NULL;
			if( ::CreateStreamOnHGlobal( hBuffer, FALSE, &pStream ) == S_OK )
			{
				pBitmap = Gdiplus::Bitmap::FromStream(pStream);
				pStream->Release();
			}
			::GlobalUnlock( hBuffer );
		}
		::GlobalFree( hBuffer );
    }
    return pBitmap ? true : false;
}


class CWaitForCheck : 
	public CDialogImpl<CWaitForCheck>
{
public:
	CWaitForCheck()
	{
		m_bStop = false;
		m_bCancel = false;
	}

	~CWaitForCheck()
	{
	}

	enum { IDD = IDD_WAITFORCHECK };

BEGIN_MSG_MAP(CWaitForCheck)
	//MESSAGE_HANDLER(WM_TIMER, OnTimer)
	MESSAGE_HANDLER(WM_INITDIALOG, OnInitDialog)
	MESSAGE_HANDLER(WM_DESTROY, OnDestroy)
	COMMAND_HANDLER(IDOK, BN_CLICKED, OnClickedOK)
	COMMAND_HANDLER(IDCANCEL, BN_CLICKED, OnClickedCancel)
	COMMAND_HANDLER(IDC_CANCEL, BN_CLICKED, OnBtnClickedCancel)
	MESSAGE_HANDLER( WM_CTLCOLORSTATIC, OnCtlColorStatic )
	MESSAGE_HANDLER( WM_ERASEBKGND, OnEraseBkgnd )
	//CHAIN_MSG_MAP(CAxDialogImpl<CWaitForCheck>)
END_MSG_MAP()

// Prototipos de controlador:
//  LRESULT MessageHandler(UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL& bHandled);
//  LRESULT CommandHandler(WORD wNotifyCode, WORD wID, HWND hWndCtl, BOOL& bHandled);
//  LRESULT NotifyHandler(int idCtrl, LPNMHDR pnmh, BOOL& bHandled);

	static VOID CALLBACK UpdateTimerProc( HWND hwnd, UINT uMsg, UINT_PTR idEvent, DWORD dwTime )
	{
		CWindow wndDlg( hwnd );
		CWindow wndProgress = wndDlg.GetDlgItem( IDC_PROGRESS1 );
		UINT nPos = (UINT) wndProgress.SendMessage( PBM_GETPOS );
		if( ++nPos > 100 )
			nPos = 0;
		wndProgress.SendMessage( PBM_SETPOS, nPos );
		if( m_bStop )
			::EndDialog( wndDlg, 0 );
	}

	//LRESULT OnTimer(UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL& bHandled)
	//{
	//	GetDlgItem( IDC_PROGRESS1 ).SendMessage( PBM_SETPOS, m_nPos++ );
	//	if( m_nPos > 100 )
	//		m_nPos = 0;
	//	return 0;
	//}

	LRESULT OnDestroy(UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL& bHandled)
	{
		Gdiplus::GdiplusShutdown( m_nToken );
		KillTimer( 1 );
		return 0;
	}

	LRESULT OnInitDialog(UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL& bHandled)
	{
		//CAxDialogImpl<CWaitForCheck>::OnInitDialog(uMsg, wParam, lParam, bHandled);

		bHandled = TRUE;
		Gdiplus::GdiplusStartupInput gpsi;
		Gdiplus::GdiplusStartup( &m_nToken, &gpsi, NULL );
		m_pBitmap = NULL;
		LoadPng( MAKEINTRESOURCE(IDB_PNG1), _T("PNG"), m_pBitmap );

		CenterWindow();
		CWindow wndProgress = GetDlgItem( IDC_PROGRESS1 );
		wndProgress.SendMessage( PBM_SETRANGE, 0, MAKELONG( 0, 100 ) );
		//wndProgress.SendMessage( PBM_SETSTEP, 1, 0 );
		//wndProgress.SendMessage( PBM_SETMARQUEE, TRUE, 0 );
		SetTimer( 1, 100, UpdateTimerProc );

		return 1;  // Permitir que el sistema establezca el foco
	}

	LRESULT OnCtlColorStatic( UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL &bHandled )
	{
		//if( GetDlgItem( IDC_GET_LICENSE ) == HWND(lParam) )
		{
			HDC hdc = reinterpret_cast<HDC>(wParam);
			SetTextColor( hdc, RGB( 140, 0, 25 ) );
			//SetBkColor( hdc, TRANSPARENT );
			SetBkMode( hdc, TRANSPARENT );
			return LRESULT(GetStockObject( NULL_BRUSH ));
		}
		return FALSE;
	}

	LRESULT OnEraseBkgnd(UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL& bHandled)
	{
		CRect rc;
		GetClientRect( &rc );
		TRIVERTEX aVertex[ 2 ] = { 0 };
		aVertex[ 0 ].Red = aVertex[ 0 ].Green = aVertex[ 0 ].Blue = 0xFF00;
		aVertex[ 1 ].x = rc.right;
		aVertex[ 1 ].y = rc.bottom;
		aVertex[ 1 ].Red = aVertex[ 1 ].Green = aVertex[ 1 ].Blue = 0xD600;
		GRADIENT_RECT gRect;
		gRect.UpperLeft = 0;
		gRect.LowerRight = 1;

		HDC hDC = HDC(wParam);
		GradientFill( hDC, aVertex, 2, &gRect, 1, GRADIENT_FILL_RECT_V );

		if( m_pBitmap )
		{
			CRect rcStatic;
			GetDlgItem( IDC_STATIC1 ).GetWindowRect( &rcStatic );
			ScreenToClient( &rcStatic );
			Gdiplus::Graphics gc( hDC );
			gc.DrawImage( m_pBitmap, INT( rc.right - m_pBitmap->GetWidth() ) / 2, INT( rcStatic.top - m_pBitmap->GetHeight() ) / 2, m_pBitmap->GetWidth(), m_pBitmap->GetHeight() );
		}


		return TRUE;
	}

	LRESULT OnClickedOK(WORD wNotifyCode, WORD wID, HWND hWndCtl, BOOL& bHandled)
	{
		//EndDialog(wID);
		return 0;
	}

	LRESULT OnClickedCancel(WORD wNotifyCode, WORD wID, HWND hWndCtl, BOOL& bHandled)
	{
		//EndDialog(wID);
		return 0;
	}

	LRESULT OnBtnClickedCancel(WORD wNotifyCode, WORD wID, HWND hWndCtl, BOOL& bHandled)
	{
		m_bCancel = true;
		return 0;
	}

	ULONG_PTR m_nToken;
	Gdiplus::Bitmap *m_pBitmap;

	static bool m_bStop;
	static bool m_bCancel;
};

__declspec(selectany) bool CWaitForCheck::m_bStop = false;
__declspec(selectany) bool CWaitForCheck::m_bCancel = false;
