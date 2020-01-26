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

#define WIN32_LEAN_AND_MEAN             // Excluir material rara vez utilizado de encabezados de Windows
// Archivos de encabezado de Windows:
#include <windows.h>


//#define _ATL_CSTRING_EXPLICIT_CONSTRUCTORS      // Algunos constructores CString serán explícitos

//#include <atlbase.h>
//#include <atlcom.h>
//#include <atlctl.h>
//#include <atlsync.h>
#include <atlstr.h>
//#include <atlsecurity.h>
//#include <atlfile.h>
//#include <atltypes.h>

// TODO: mencionar aquí los encabezados adicionales que el programa necesita
