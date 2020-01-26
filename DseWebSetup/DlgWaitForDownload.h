// WaitForCheck.h: declaración de CWaitForDownload

#pragma once

#include "resource.h"       // Símbolos principales

#include <atlhost.h>

using namespace ATL;

#pragma comment(lib, "Msimg32.lib")
// CWaitForDownload

class CWaitForDownload : 
	public CAxDialogImpl<CWaitForDownload>
{
public:
	CWaitForDownload()
	{
		m_bStop = false;
		m_bCancel = false;
	}

	~CWaitForDownload()
	{
	}

	enum { IDD = IDD_DLGWAIT };

BEGIN_MSG_MAP(CWaitForDownload)
	//MESSAGE_HANDLER(WM_TIMER, OnTimer)
	MESSAGE_HANDLER(WM_INITDIALOG, OnInitDialog)
	MESSAGE_HANDLER(WM_DESTROY, OnDestroy)
	COMMAND_HANDLER(IDOK, BN_CLICKED, OnClickedOK)
	COMMAND_HANDLER(IDCANCEL, BN_CLICKED, OnClickedCancel)
	COMMAND_HANDLER(IDC_CANCEL, BN_CLICKED, OnBtnClickedCancel)
	MESSAGE_HANDLER( WM_CTLCOLORSTATIC, OnCtlColorStatic )
	MESSAGE_HANDLER( WM_ERASEBKGND, OnEraseBkgnd )
	CHAIN_MSG_MAP(CAxDialogImpl<CWaitForDownload>)
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
		KillTimer( 1 );
		return 0;
	}

	LRESULT OnInitDialog(UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL& bHandled)
	{
		CAxDialogImpl<CWaitForDownload>::OnInitDialog(uMsg, wParam, lParam, bHandled);
		bHandled = TRUE;
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
		RECT rc;
		GetClientRect( &rc );
		TRIVERTEX aVertex[ 2 ] = { 0 };
		aVertex[ 0 ].Red = aVertex[ 0 ].Green = aVertex[ 0 ].Blue = 0xFF00;
		aVertex[ 1 ].x = rc.right;
		aVertex[ 1 ].y = rc.bottom;
		aVertex[ 1 ].Red = aVertex[ 1 ].Green = aVertex[ 1 ].Blue = 0xD600;
		GRADIENT_RECT gRect;
		gRect.UpperLeft = 0;
		gRect.LowerRight = 1;

		GradientFill( HDC(wParam), aVertex, 2, &gRect, 1, GRADIENT_FILL_RECT_V );
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

	static bool m_bStop;
	static bool m_bCancel;
};

__declspec(selectany) bool CWaitForDownload::m_bStop = false;
__declspec(selectany) bool CWaitForDownload::m_bCancel = false;
