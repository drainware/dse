// dllmain.cpp : Implementation of DllMain.

#include "stdafx.h"
#include "resource.h"
#include "dllmain.h"

CDrainwareShellExtModule _AtlModule;
HINSTANCE g_hInst;
// DLL Entry Point
extern "C" BOOL WINAPI DllMain(HINSTANCE hInstance, DWORD dwReason, LPVOID lpReserved)
{
	g_hInst = hInstance;
	return _AtlModule.DllMain(dwReason, lpReserved); 
}
