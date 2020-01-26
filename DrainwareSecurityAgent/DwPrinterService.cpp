// DwPrinterService.cpp: implementación de CDwPrinterService

#include "stdafx.h"
#include "DwPrinterService.h"
#include "IUserNotify.h"
#include "UserData.h"
#include "DwService.h"
#include "ISecurityAgent.h"

extern ISecurityAgent *g_pSecurityAgent;
// CDwPrinterService

STDMETHODIMP CDwPrinterService::InterfaceSupportsErrorInfo(REFIID riid)
{
	static const IID* const arr[] = 
	{
		&IID_IDwPrinterService
	};

	for (int i=0; i < sizeof(arr) / sizeof(arr[0]); i++)
	{
		if (InlineIsEqualGUID(*arr[i],riid))
			return S_OK;
	}
	return S_FALSE;
}


STDMETHODIMP CDwPrinterService::PrintJob( BSTR bstrDocName, BSTR bstrPath, BSTR bstrPrinter, BSTR bstrUserName )
{
	g_pSecurityAgent->PrintJob( bstrDocName, bstrPath, bstrPrinter, bstrUserName );
	return S_OK;
}

STDMETHODIMP CDwPrinterService::IsClosing( VARIANT_BOOL *pRet )
{
	if( !pRet )
		return E_INVALIDARG;
	*pRet = g_pSecurityAgent->IsClosing() ? VARIANT_TRUE : VARIANT_FALSE;
	return S_OK;
}
