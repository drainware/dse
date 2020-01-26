// stdafx.h: archivo de inclusión de los archivos de inclusión estándar del sistema
// o archivos de inclusión específicos de un proyecto utilizados frecuentemente,
// pero rara vez modificados

#pragma once

#ifndef STRICT
#define STRICT
#endif

#define _WIN32_DCOM

#include "targetver.h"
//#undef NTDDI_VERSION
//#undef _WIN32_WINNT
//#define _WIN32_WINNT 0x0501
//#define NTDDI_VERSION 0x05010200

//#define _ATL_APARTMENT_THREADED

#define _ATL_NO_AUTOMATIC_NAMESPACE

#define _ATL_CSTRING_EXPLICIT_CONSTRUCTORS	// Algunos constructores CString serán explícitos


#define ATL_NO_ASSERT_ON_DESTROY_NONEXISTENT_WINDOW

#include "resource.h"
#include <atlbase.h>
#include <atlcom.h>
#include <atlctl.h>
#include <atlsync.h>
#include <atlstr.h>
#include <atlsecurity.h>
#include <atlfile.h>
#include <atltypes.h>
#include <Dbt.h>

using namespace ATL;
