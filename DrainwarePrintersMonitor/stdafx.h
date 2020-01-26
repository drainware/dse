// stdafx.h: archivo de inclusión de los archivos de inclusión estándar del sistema
// o archivos de inclusión específicos de un proyecto utilizados frecuentemente,
// pero rara vez modificados
//

#pragma once

#define _WIN32_DCOM

#include "targetver.h"
//#undef NTDDI_VERSION
//#undef _WIN32_WINNT
//#define _WIN32_WINNT 0x0501
//#define NTDDI_VERSION 0x05010200

//#define WIN32_LEAN_AND_MEAN             // Excluir material rara vez utilizado de encabezados de Windows
// Archivos de encabezado de Windows:
#define _ATL_FREE_THREADED

#define _ATL_NO_AUTOMATIC_NAMESPACE

#define _ATL_CSTRING_EXPLICIT_CONSTRUCTORS	// Algunos constructores CString serán explícitos


#define ATL_NO_ASSERT_ON_DESTROY_NONEXISTENT_WINDOW

#include <atlbase.h>
#include <atlcom.h>
#include <atlctl.h>
#include <atlwin.h>
#include <atlsync.h>
#include <atlstr.h>
#include <atlcoll.h>
#include <atlfile.h>

//#include <windows.h>
#include <Winsplp.h>


// TODO: mencionar aquí los encabezados adicionales que el programa necesita

using namespace ATL;