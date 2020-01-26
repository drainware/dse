#pragma once

enum eTrayIcons
{
	TRAY_ICONNONE = 0,
	TRAY_ICONINFORMATION,
	TRAY_ICONWARNING,
	TRAY_ICONERROR
};

#define WM_SHOWTRAYMSG WM_USER + 18

struct MsgItem
{
	CString m_strMessage;
	UINT m_uFlags;
};

class CTrayWindow : public ATL::CWindowImpl< CTrayWindow >
{
public:

	CTrayWindow() : m_bTimer( false )
	{
		m_dwThreadID = GetCurrentThreadId();
	}
	static const DWORD m_dwShowTime = 3000; //in milliseconds

BEGIN_MSG_MAP(CTrayWindow)
	MESSAGE_HANDLER( WM_PAINT, OnPaint )
	MESSAGE_HANDLER( WM_CREATE, OnCreate )
	MESSAGE_HANDLER( WM_DESTROY, OnDestroy )
	MESSAGE_HANDLER( WM_SHOWTRAYMSG, OnShowTrayMsg )
END_MSG_MAP()

LRESULT OnCreate( UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL& bHandled );
LRESULT OnDestroy( UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL& bHandled );
LRESULT OnPaint( UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL& bHandled );
LRESULT OnShowTrayMsg( UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL& bHandled );
//Public Methods:

	void ShowMessage( PCTSTR szMessage, UINT uFlags );
	static void CALLBACK TimerProc( HWND hwnd, UINT uMsg, UINT_PTR idEvent, DWORD dwTime );

private:
	void OnTimer();
	void Init();
	void FillSolidRect( HDC hDC, LPCRECT lpRect, COLORREF clr );
	void FillSolidRect( HDC hDC, int x, int y, int cx, int cy, COLORREF clr );
	void DrawBorder( HDC hDC, int x, int y, int cx, int cy, int nWidth, COLORREF clrBorder );

	CString m_strMessage;
	UINT m_uFlags;
	HBITMAP m_bmpClose;
	HBITMAP m_bmpDwLogo;

	DWORD m_dwStart;
	int m_nX;
	int m_nStart, m_nEnd;
	float m_fDif;
	float m_fPos;
	bool m_bShowing, m_bDown;
	DWORD m_dwThreadID;
	CAtlArray< MsgItem > m_aMsg;
	CCriticalSection m_csMsg;
	bool m_bTimer;
};
