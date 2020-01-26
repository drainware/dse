#include "stdafx.h"
#include "TrayWindow.h"
#include "..\DwLib\DwLib.h"

LRESULT CTrayWindow::OnCreate( UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL& bHandled )
{
	m_bmpClose = (HBITMAP)::LoadImage( GetModuleHandle( NULL ), MAKEINTRESOURCE(IDB_TRAYCLOSE), IMAGE_BITMAP, 28, 14, LR_CREATEDIBSECTION );
	m_bmpDwLogo = (HBITMAP)::LoadImage( GetModuleHandle( NULL ), MAKEINTRESOURCE(IDB_TRAYBACKGROUND), IMAGE_BITMAP, 260, 92, LR_CREATEDIBSECTION );
	return 0;
}

LRESULT CTrayWindow::OnDestroy( UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL& bHandled )
{
	KillTimer( reinterpret_cast<UINT_PTR>(this) );
	if( m_bmpClose )
		::DeleteObject( m_bmpClose );
	if( m_bmpDwLogo )
		::DeleteObject( m_bmpDwLogo );
	return 0;
}

LRESULT CTrayWindow::OnPaint( UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL& bHandled )
{
	CRect rcUpdate;
	if( !GetUpdateRect( rcUpdate ) )
		return 0;
	PAINTSTRUCT ps;
	HDC hDC = BeginPaint( &ps );

	CRect rcClient;
	GetClientRect( rcClient );
	//DrawBorder( hDC, rcClient.left, rcClient.top, rcClient.right, rcClient.bottom, 2, RGB(168, 10,11) );

	HDC hdcMem = ::CreateCompatibleDC( hDC );
	HBITMAP hBmpOld = (HBITMAP)::SelectObject( hdcMem, m_bmpDwLogo );
	BitBlt( hDC, 0, 0, 260, 92, hdcMem, 0, 0, SRCCOPY );
	(HBITMAP)::SelectObject( hdcMem, m_bmpClose );
	BitBlt( hDC, rcClient.right - 20, rcClient.top + 6, 14, 14, hdcMem, 0, 0, SRCCOPY );
	::SelectObject( hdcMem, hBmpOld );

	LPCWSTR szRes = IDI_INFORMATION;
	if( m_uFlags == TRAY_ICONWARNING )
		szRes = IDI_WARNING;
	else if( m_uFlags == TRAY_ICONERROR )
		szRes = IDI_ERROR;
	HICON hIcon = (HICON)LoadImage( NULL, szRes, IMAGE_ICON, 32, 32, LR_SHARED );
	DrawIcon( hDC, 10, 32, hIcon );
	//DestroyIcon( hIcon );

	//rcClient.left += 32 + 16 + 2; //Text rect
	//rcClient.bottom -= 8 + 2;
	//rcClient.right -= 20 + 4;
	//rcClient.top += 8 + 2;
	rcClient.left += 32 + 16 + 2; //Text rect
	rcClient.bottom -= 2;
	rcClient.right -= + 4;
	rcClient.top += 32;

	HFONT hFont = (HFONT)GetStockObject( DEFAULT_GUI_FONT );
	HFONT hFontOld = (HFONT)::SelectObject( hDC, hFont );
	int nOldMode = ::SetBkMode( hDC, TRANSPARENT );
	//ExtTextOut( hDC, rcClient.left, rcClient.top, ETO_CLIPPED, rcClient, m_strMessage, m_strMessage.GetLength(), NULL );
	DrawText( hDC, m_strMessage, m_strMessage.GetLength(), rcClient, DT_WORDBREAK );
	::SetBkMode( hDC, nOldMode );
	::SelectObject( hDC, hFontOld );
	DeleteObject( hFont );
	EndPaint( &ps );
	return 0;
}

LRESULT CTrayWindow::OnShowTrayMsg( UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL& bHandled )
{
	{
		PCTSTR szMessage = PCTSTR(wParam);
		UINT uFlags = UINT(lParam);
		CAutoCS acs( m_csMsg );
		MsgItem &it = m_aMsg[ m_aMsg.Add() ];
		it.m_strMessage = szMessage;
		it.m_uFlags = uFlags;
	}
	if( !m_strMessage.GetLength() )
		Init();

	CAutoCS acs( m_csMsg );
	if( !m_bTimer )
	{
		m_bTimer = true;
		SetTimer( reinterpret_cast<UINT_PTR>(this), 25, &CTrayWindow::TimerProc );
	}
	return FALSE;
}

void CTrayWindow::ShowMessage( PCTSTR szMessage, UINT uFlags )
{
	PostMessage( WM_SHOWTRAYMSG, (WPARAM)szMessage, uFlags );
}

void CALLBACK CTrayWindow::TimerProc( HWND hwnd, UINT uMsg, UINT_PTR idEvent, DWORD dwTime )
{
	CTrayWindow *pThis = reinterpret_cast<CTrayWindow *>(idEvent);
	pThis->OnTimer();
}


void CTrayWindow::Init()
{
	CRect rcArea, rcWin;
	SystemParametersInfo( SPI_GETWORKAREA, 0, &rcArea, 0 );
	GetWindowRect( &rcWin );

	m_nX = rcArea.right - rcWin.Width();
	SetWindowPos( HWND_TOP, m_nX, rcArea.bottom, 0, 0, SWP_NOSIZE | SWP_SHOWWINDOW );

	m_nStart = rcArea.bottom;
	m_nEnd = rcArea.bottom - rcWin.Height();
	m_fDif = -float(rcWin.Height()) / 40.0f; // for 1 sec, updating every 25 ms
	m_fPos = float(rcArea.bottom);
	m_bDown = m_bShowing = false;
	{
		CAutoCS acs( m_csMsg );
		MsgItem &it = m_aMsg[ 0 ];
		m_strMessage = it.m_strMessage;
		m_uFlags = it.m_uFlags;
		m_aMsg.RemoveAt( 0 );
	}
}

void CTrayWindow::OnTimer()
{
	if( m_bShowing )
	{
		if( GetTickCount() - m_dwStart >= m_dwShowTime )
		{
			m_bShowing = false;
			m_bDown = true;
		}
		return;
	}
	m_fPos += m_fDif;

	int nY = int(m_fPos);

	if( m_bDown )
	{
		if( nY >= m_nStart )
		{
			ShowWindow( SW_HIDE );

			bool bKill = true;
			{
				CAutoCS acs(m_csMsg);
				if( m_aMsg.GetCount() )
					bKill = false;
				else
				{
					m_strMessage.Empty();
				}
			}
			if( bKill )
			{
				CAutoCS acs(m_csMsg);
				m_bTimer = false;
				KillTimer( reinterpret_cast<UINT_PTR>(this) );
			}
			else
				Init();
			return;
		}
	}
	else if( nY <= m_nEnd )
	{
		nY = m_nEnd;
		m_bShowing = true;
		m_dwStart = GetTickCount();
		m_fDif = -m_fDif;
	}

	int nHeight = m_nStart - m_nEnd;
	int nPos = m_nStart - nY;
	BYTE bAlpha = BYTE( 255 * nPos / nHeight );
	SetLayeredWindowAttributes( m_hWnd, 0, bAlpha, LWA_ALPHA );
	SetWindowPos( HWND_TOPMOST, m_nX, nY, 0, 0,  SWP_NOSIZE | SWP_SHOWWINDOW );
}

void CTrayWindow::FillSolidRect( HDC hDC, LPCRECT lpRect, COLORREF clr )
{
	COLORREF clrOld = ::SetBkColor( hDC, clr);
	if(clrOld != CLR_INVALID)
	{
		::ExtTextOut( hDC, 0, 0, ETO_OPAQUE, lpRect, NULL, 0, NULL);
		::SetBkColor( hDC, clrOld);
	}
}

void CTrayWindow::FillSolidRect( HDC hDC, int x, int y, int cx, int cy, COLORREF clr )
{
	RECT rect = { x, y, x + cx, y + cy };
	FillSolidRect( hDC, &rect, clr);
}

void CTrayWindow::DrawBorder( HDC hDC, int x, int y, int cx, int cy, int nWidth, COLORREF clrBorder )
{
	FillSolidRect( hDC, x, y, cx - nWidth, nWidth, clrBorder );
	FillSolidRect( hDC, x, y, nWidth, cy - nWidth, clrBorder );
	FillSolidRect( hDC, x + cx, y, -nWidth, cy, clrBorder );
	FillSolidRect( hDC, x, y + cy, cx, -nWidth, clrBorder );
}