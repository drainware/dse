// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

#include "targetver.h"
#undef NTDDI_VERSION
#undef _WIN32_WINNT
#define _WIN32_WINNT 0x0501
#define NTDDI_VERSION 0x05010200

#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
// Windows Header Files:
#include <windows.h>

// C RunTime Header Files
#include <stdlib.h>
#include <malloc.h>
#include <memory.h>
#include <tchar.h>

#define _ATL_CSTRING_EXPLICIT_CONSTRUCTORS      // some CString constructors will be explicit

#include <atlbase.h>
#include <atlstr.h>
#include <atlsync.h>
#include <atlfile.h>
#include <atlsecurity.h>

// TODO: reference additional headers your program requires here
