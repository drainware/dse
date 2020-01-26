// DrainwareShellExt.h : Declaration of the CDrainwareShellExt

#pragma once
#include "resource.h"       // main symbols
#include <ShlObj.h>


#if defined(_WIN32_WCE) && !defined(_CE_DCOM) && !defined(_CE_ALLOW_SINGLE_THREADED_OBJECTS_IN_MTA)
#error "Single-threaded COM objects are not properly supported on Windows CE platform, such as the Windows Mobile platforms that do not include full DCOM support. Define _CE_ALLOW_SINGLE_THREADED_OBJECTS_IN_MTA to force ATL to support creating single-thread COM object's and allow use of it's single-threaded COM object implementations. The threading model in your rgs file was set to 'Free' as that is the only threading model supported in non DCOM Windows CE platforms."
#endif

using namespace ATL;


// CDrainwareShellExt

extern const CLSID CLSID_DrainwareShellExt;

class ATL_NO_VTABLE CDrainwareShellExt :
	public CComObjectRootEx<CComSingleThreadModel>,
	public CComCoClass<CDrainwareShellExt, &CLSID_DrainwareShellExt>,
	public IShellExtInit,
    public IContextMenu
	//public ICopyHook //Only for directories
{
public:

	enum
	{
		FT_NONE = 0,
		FT_NETWORK_DEVICE,
		FT_GOOGLE_DRIVE,
		FT_DROPBOX_DRIVE,
		FT_SKY_DRIVE
	}NET_FOLDER_TYPE;

	CDrainwareShellExt();

DECLARE_REGISTRY_RESOURCEID(IDR_DRAINWARESHELLEXT)


BEGIN_COM_MAP(CDrainwareShellExt)
	COM_INTERFACE_ENTRY(IShellExtInit)
	COM_INTERFACE_ENTRY(IContextMenu)
	//COM_INTERFACE_ENTRY(ICopyHook)
	//COM_INTERFACE_ENTRY_IID(IID_IShellCopyHook , CDrainwareShellExt)
END_COM_MAP()


	DECLARE_PROTECT_FINAL_CONSTRUCT()

	HRESULT FinalConstruct()
	{
		return S_OK;
	}

	void FinalRelease()
	{
	}

public:

	// IShellExtInit
	STDMETHODIMP Initialize(LPCITEMIDLIST, LPDATAOBJECT, HKEY);
  
	// IContextMenu
    STDMETHODIMP GetCommandString( UINT_PTR idCmd, UINT uFlags,UINT* pwReserved, LPSTR pszName, UINT cchMax ) { return E_NOTIMPL; };
    STDMETHODIMP InvokeCommand(LPCMINVOKECOMMANDINFO);
    STDMETHODIMP QueryContextMenu(HMENU,UINT,UINT,UINT,UINT);
	//ICopyHook
    //UINT WINAPI CopyCallback( HWND hwnd, UINT wFunc, UINT wFlags, PCTSTR pszSrcFile, DWORD dwSrcAttribs, LPCTSTR pszDestFile, DWORD dwDestAttribs );

	static bool IsUSB( LPCTSTR szDrive );
private:
	ULONG IsInetFolder( LPCTSTR szFolder );
	static int SQLiteCallback( void *pUserData, int argc, char **argv, char **azColName );
	static DWORD WINAPI ThreadDlg( PVOID pVoid );
	//CAtlArray< CString > m_aNetPaths;
	CAtlArray< CString > m_aDropBoxPaths;
	CAtlArray< CString > m_aGDrivePaths;
	CAtlArray< CString > m_aSkyDrivePaths;
	CAtlArray< CString > m_aGDriveUsers;
};

OBJECT_ENTRY_AUTO( CLSID_DrainwareShellExt, CDrainwareShellExt )
