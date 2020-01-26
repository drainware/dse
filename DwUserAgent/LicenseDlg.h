#pragma once

class CLicenseDlg : public CDialogImpl< CLicenseDlg >
{
public:
	enum { IDD = IDD_LICENSE_DLG };

	BEGIN_MSG_MAP( CLoginDlg )
		MESSAGE_HANDLER( WM_INITDIALOG, OnInitDialog )
		MESSAGE_HANDLER( WM_SHOWWINDOW, OnShowWindow )
		COMMAND_ID_HANDLER( IDOK, OnOK )
		COMMAND_ID_HANDLER( IDCANCEL, OnCancel )
		MESSAGE_HANDLER( WM_COMMAND, OnCommand )
		MESSAGE_HANDLER( WM_DESTROY, OnDestroy )
		//MESSAGE_HANDLER( WM_CTLCOLORSTATIC, OnCtlColorStatic )
		MESSAGE_HANDLER( WM_DRAWITEM, OnDrawItem );
	ALT_MSG_MAP( 1 )
		MESSAGE_HANDLER( WM_PASTE, OnPaste )
	END_MSG_MAP()

	CLicenseDlg() : m_ed1( _T("EDIT"), this, 1 )
	{}

	LRESULT OnInitDialog( UINT uMsg, WPARAM wParam, LPARAM, BOOL &bHandled )
	{
		m_ed1.SubclassWindow( GetDlgItem( IDC_EDIT1 ) );
		m_ed1.SendMessage( EM_SETLIMITTEXT, 4, 0 );
		GetDlgItem( IDC_EDIT2 ).SendMessage( EM_SETLIMITTEXT, 4, 0 );
		GetDlgItem( IDC_EDIT3 ).SendMessage( EM_SETLIMITTEXT, 4, 0 );
		GetDlgItem( IDC_EDIT4 ).SendMessage( EM_SETLIMITTEXT, 4, 0 );
		return TRUE;
	}

	LRESULT OnDestroy( UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL &bHandled )
	{
		m_ed1.UnsubclassWindow();
		return FALSE;
	}

	LRESULT OnPaste( UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL &bHandled )
	{
		OpenClipboard();
		HANDLE hText = GetClipboardData( CF_UNICODETEXT );
		PWSTR szText = reinterpret_cast<PWSTR>(GlobalLock( hText ));

		if( szText && lstrlen( szText ) )
		{
			const int nSize  = 32;
			WCHAR aBuffers[ 4 ][ nSize ];
			if( swscanf_s( szText, _T("%4s-%4s-%4s-%4s"), aBuffers[ 0 ], nSize, aBuffers[ 1 ], nSize, aBuffers[ 2 ], nSize, aBuffers[ 3 ], nSize ) == 4 )
			{
				m_ed1.SetWindowText( aBuffers[ 0 ] );
				GetDlgItem( IDC_EDIT2 ).SetWindowText( aBuffers[ 1 ] );
				GetDlgItem( IDC_EDIT3 ).SetWindowText( aBuffers[ 2 ] );
				GetDlgItem( IDC_EDIT4 ).SetWindowText( aBuffers[ 3 ] );
			}
		}

		GlobalUnlock( hText );
		CloseClipboard();
		return FALSE;
	}

	LRESULT OnCommand( UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL &bHandled )
	{
		if( HIWORD( wParam ) == EN_CHANGE )
		{
			CWindow wnd = HWND(lParam);
			if( wnd && wnd.GetWindowTextLength() == 4 )
			{
				CWindow wndNext = GetNextDlgTabItem( wnd );
				wndNext.SetFocus();
				wndNext.SendMessage( EM_SETSEL, 0, -1 );
				return FALSE;
			}
		}
		else if( LOWORD(wParam) == IDC_GET_LICENSE && HIWORD(wParam) == STN_CLICKED )
		{
			ShellExecute( NULL, NULL, _T("http://www.drainware.com/"), NULL, NULL, SW_SHOWNORMAL );
		}

		return TRUE;
	}

	LRESULT OnDrawItem(  UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL &bHandled )
	{
		LPDRAWITEMSTRUCT pDIS = (LPDRAWITEMSTRUCT)lParam;
		SetTextColor( pDIS->hDC, RGB( 0, 0, 255 ) );
		CWindow wndStatic = GetDlgItem( IDC_GET_LICENSE );
		//TCHAR szText[ MAX_PATH ];
		//int nLen = wndStatic.GetWindowText( szText, MAX_PATH );
		TCHAR szText[] = _T("If you don't have a license, you can get one here for free");
		LOGFONT lf = { 0 };
		GetObject( wndStatic.GetFont(), sizeof(LOGFONT), &lf ); 
		lf.lfUnderline = TRUE;
		HFONT hFont = CreateFontIndirect( &lf );
		HFONT hFontOld = (HFONT)SelectObject( pDIS->hDC, hFont );
		DrawText( pDIS->hDC, szText, -1, &pDIS->rcItem, DT_CENTER );
		SelectObject( pDIS->hDC, hFontOld );
		DeleteObject( hFont );

		return TRUE;
	}

	LRESULT OnCtlColorStatic( UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL &bHandled )
	{
		if( GetDlgItem( IDC_GET_LICENSE ) == HWND(lParam) )
		{
			HDC hdc = reinterpret_cast<HDC>(wParam);
			SetTextColor( hdc, RGB( 0, 0, 255 ) );
			//SetBkColor( hdc, TRANSPARENT );
			SetBkMode( hdc, TRANSPARENT );
			return LRESULT(GetStockObject( NULL_BRUSH ));
		}
		return FALSE;
	}

	LRESULT OnShowWindow( UINT uMsg, WPARAM wParam, LPARAM, BOOL &bHandled )
	{
		if( wParam )
			SetWindowPos( HWND_TOP, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE );
		return 0;
	}

	LRESULT OnOK( UINT nCtl, UINT nID, HWND hWnd, BOOL &bHandled )
	{
		GetDlgItemText( IDC_EDIT1, m_strLic1.m_str );
		GetDlgItemText( IDC_EDIT2, m_strLic2.m_str );
		GetDlgItemText( IDC_EDIT3, m_strLic3.m_str );
		GetDlgItemText( IDC_EDIT4, m_strLic4.m_str );

		EndDialog( IDOK );
		return 0;
	}

	LRESULT OnCancel( UINT nCtl, UINT nID, HWND hWnd, BOOL &bHandled )
	{
		EndDialog( IDCANCEL );
		return 0;
	}

	CComBSTR m_strLic1;
	CComBSTR m_strLic2;
	CComBSTR m_strLic3;
	CComBSTR m_strLic4;

	CContainedWindow m_ed1;
};
