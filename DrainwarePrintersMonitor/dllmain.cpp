// dllmain.cpp : Define el punto de entrada de la aplicación DLL.
#include "stdafx.h"
#include "PrinterMonitor.h"

MONITOR2 g_Monitor =
{
	sizeof( MONITOR2 ),
	CPrinterMonitor::EnumPorts,
	CPrinterMonitor::OpenPort,
	NULL,//OpenPortEx
	CPrinterMonitor::StartDocPort,
	CPrinterMonitor::WritePort,
	CPrinterMonitor::ReadPort,
	CPrinterMonitor::EndDocPort,
	CPrinterMonitor::ClosePort,
	NULL, //CPrinterMonitor::AddPort,
	NULL, //CPrinterMonitor::AddPortEx,
	NULL, //CPrinterMonitor::ConfigurePort,
	NULL, //CPrinterMonitor::DeletePort,
	NULL, //CPrinterMonitor::GetPrinterDataFromPort,
	NULL, //CPrinterMonitor::SetPortTimeOuts,
	CPrinterMonitor::XcvOpenPort,
	CPrinterMonitor::XcvDataPort,
	CPrinterMonitor::XcvClosePort,
	CPrinterMonitor::Shutdown,
	NULL //CPrinterMonitor::SendRecvBidiDataFromPort
};

MONITORUI g_MonitorUI = {
    sizeof(MONITORUI),
    NULL, //rcAddPortUI,
    NULL, //rcConfigurePortUI,
    NULL //rcDeletePortUI
};

LPMONITOR2 WINAPI InitializePrintMonitor2( PMONITORINIT pMonitorInit, PHANDLE phMonitor )
{
	//MessageBox( GetActiveWindow(), _T("Debug Monitor"), _T("Msg"), MB_OK );
	*phMonitor = (PHANDLE)pMonitorInit;
	return &g_Monitor;
}

PMONITORUI WINAPI InitializePrintMonitorUI()
{
	//TODO:Continue here
	MessageBox( GetActiveWindow(), _T("InitializePrintMonitorUI"), _T("Msg"), MB_OK );
	return &g_MonitorUI;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		CoInitializeEx( NULL, COINIT_MULTITHREADED );
		CoInitializeSecurity( NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_NONE, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL );

		CPrinterMonitor::m_hDll = hModule;
		DisableThreadLibraryCalls( hModule );
		CPrinterMonitor::InitThreadWatch();
		//CPrinterMonitor::LoadDefaultPorts();
	break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	break;
	case DLL_PROCESS_DETACH:
		//CPrinterMonitor::RestoreDefaultPorts();
		CPrinterMonitor::CloseThreadWatch();
		CoUninitialize();
	break;
	}
	return TRUE;
}

