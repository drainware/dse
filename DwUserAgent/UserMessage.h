#pragma once

#include "resource.h"       // Símbolos principales

#include <atlhost.h>

using namespace ATL;

// CWaitForCheck

class CUserMessage : 
	public CAxDialogImpl<CUserMessage>
{
public:
	CUserMessage( BSTR bstrMsg ) : m_strMsg( bstrMsg )
	{
	}

	~CUserMessage()
	{
	}

	enum { IDD = IDD_USER_MSG };

BEGIN_MSG_MAP(CUserMessage)
	//MESSAGE_HANDLER(WM_TIMER, OnTimer)
	MESSAGE_HANDLER(WM_INITDIALOG, OnInitDialog)
	COMMAND_HANDLER(IDOK, BN_CLICKED, OnClickedOK)
	COMMAND_HANDLER(IDCANCEL, BN_CLICKED, OnClickedCancel)
	MESSAGE_HANDLER( WM_CTLCOLORSTATIC, OnCtlColorStatic )
	CHAIN_MSG_MAP(CAxDialogImpl<CUserMessage>)
END_MSG_MAP()

// Prototipos de controlador:
//  LRESULT MessageHandler(UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL& bHandled);
//  LRESULT CommandHandler(WORD wNotifyCode, WORD wID, HWND hWndCtl, BOOL& bHandled);
//  LRESULT NotifyHandler(int idCtrl, LPNMHDR pnmh, BOOL& bHandled);

	LRESULT OnInitDialog(UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL& bHandled)
	{
		CAxDialogImpl<CUserMessage>::OnInitDialog(uMsg, wParam, lParam, bHandled);
		bHandled = TRUE;
		GetDlgItem( IDC_STATIC4 ).SetWindowText( m_strMsg );
		return 1;  // Permitir que el sistema establezca el foco
	}

	LRESULT OnCtlColorStatic( UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL &bHandled )
	{
		//if( GetDlgItem( IDC_GET_LICENSE ) == HWND(lParam) )
		{
			HDC hdc = reinterpret_cast<HDC>(wParam);
			SetTextColor( hdc, RGB( 0, 0, 255 ) );
			//SetBkColor( hdc, TRANSPARENT );
			SetBkMode( hdc, TRANSPARENT );
			return LRESULT(GetStockObject( NULL_BRUSH ));
		}
		return FALSE;
	}

	LRESULT OnClickedOK(WORD wNotifyCode, WORD wID, HWND hWndCtl, BOOL& bHandled)
	{
		EndDialog(wID);
		return 0;
	}

	LRESULT OnClickedCancel(WORD wNotifyCode, WORD wID, HWND hWndCtl, BOOL& bHandled)
	{
		EndDialog(wID);
		return 0;
	}

	CString m_strMsg;
};
