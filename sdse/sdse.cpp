// sdse.cpp : Defines the entry point for the application.
//

#include "stdafx.h"
#include "sdse.h"


int APIENTRY _tWinMain(_In_ HINSTANCE hInstance,
                     _In_opt_ HINSTANCE hPrevInstance,
                     _In_ LPTSTR    lpCmdLine,
                     _In_ int       nCmdShow)
{
	UNREFERENCED_PARAMETER(hInstance);
	UNREFERENCED_PARAMETER(hPrevInstance);
	UNREFERENCED_PARAMETER(nCmdShow);
	UNREFERENCED_PARAMETER(lpCmdLine);

	SC_HANDLE hSCM = ::OpenSCManager( NULL, NULL, SC_MANAGER_ALL_ACCESS );
	if( hSCM )
	{
		SC_HANDLE hService = OpenService( hSCM, _T("DrainwareSecurityAgent"), SERVICE_ALL_ACCESS );
		if( hService )
		{
			SERVICE_STATUS ss;
			ControlService( hService, SERVICE_CONTROL_STOP, &ss );

			SERVICE_STATUS_PROCESS ssp;
			DWORD dwNeeded;
			int nRetries = 0;
			while( nRetries++ < 1200 ) //try for two minutes
			{
				if( !QueryServiceStatusEx( hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(SERVICE_STATUS_PROCESS), &dwNeeded ) )
					break;
				if( ssp.dwCurrentState == SERVICE_STOPPED )
					break;
				Sleep( 100 );
			}
			CloseServiceHandle( hService );
		}
		CloseServiceHandle( hSCM );
	}


 	// TODO: Place code here.
	return 0;
}

