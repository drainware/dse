// DwPrinterService.h: declaración de CDwPrinterService

#pragma once
#include "resource.h"       // Símbolos principales



#include "DrainwareSecurityAgent_i.h"
#include "_IDwPrinterServiceEvents_CP.h"



#if defined(_WIN32_WCE) && !defined(_CE_DCOM) && !defined(_CE_ALLOW_SINGLE_THREADED_OBJECTS_IN_MTA)
#error "Los objetos COM de un único subproceso no se admiten completamente en la plataforma Windows CE, como por ejemplo la plataforma Windows Mobile, que no incluye la compatibilidad DCOM completa. Defina _CE_ALLOW_SINGLE_THREADED_OBJECTS_IN_MTA para que ATL tenga que admitir la creación de objetos COM de un único subproceso y permitir el uso de sus implementaciones de este tipo de objetos. El modelo de subprocesos del archivo rgs estaba establecido en 'Free' ya que es el único modelo de subprocesos admitido en plataformas que no son Windows CE DCOM."
#endif

using namespace ATL;


// CDwPrinterService

class ATL_NO_VTABLE CDwPrinterService :
	public CComObjectRootEx<CComSingleThreadModel>,
	public CComCoClass<CDwPrinterService, &CLSID_DwPrinterService>,
	public ISupportErrorInfo,
	public IConnectionPointContainerImpl<CDwPrinterService>,
	public CProxy_IDwPrinterServiceEvents<CDwPrinterService>,
	public IDispatchImpl<IDwPrinterService, &IID_IDwPrinterService, &LIBID_DrainwareSecurityAgentLib, /*wMajor =*/ 1, /*wMinor =*/ 0>
{
public:
	CDwPrinterService()
	{
	}

DECLARE_REGISTRY_RESOURCEID(IDR_DWPRINTERSERVICE)


BEGIN_COM_MAP(CDwPrinterService)
	COM_INTERFACE_ENTRY(IDwPrinterService)
	COM_INTERFACE_ENTRY(IDispatch)
	COM_INTERFACE_ENTRY(ISupportErrorInfo)
	COM_INTERFACE_ENTRY(IConnectionPointContainer)
END_COM_MAP()

BEGIN_CONNECTION_POINT_MAP(CDwPrinterService)
	CONNECTION_POINT_ENTRY(__uuidof(_IDwPrinterServiceEvents))
END_CONNECTION_POINT_MAP()

//ISupportsErrorInfo
	STDMETHOD(InterfaceSupportsErrorInfo)(REFIID riid);


	DECLARE_PROTECT_FINAL_CONSTRUCT()

	HRESULT FinalConstruct()
	{
		return S_OK;
	}

	void FinalRelease()
	{
	}

public:



	STDMETHOD(PrintJob)(BSTR bstrDocName, BSTR bstrPath, BSTR bstrPrinter, BSTR bstrPrinterName);
	STDMETHOD(IsClosing)( VARIANT_BOOL *pRet );
};

OBJECT_ENTRY_AUTO(__uuidof(DwPrinterService), CDwPrinterService)
