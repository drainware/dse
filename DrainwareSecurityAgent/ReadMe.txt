========================================================================
    ACTIVE TEMPLATE LIBRARY: DrainwareSecurityAgent 
    Información general del proyecto
========================================================================

AppWizard ha creado este proyecto DrainwareSecurityAgent para que lo 
utilice como punto de partida para escribir su Servicio (EXE)

Este archivo contiene un resumen de lo que encontrará en todos los 
archivos que constituyen el proyecto.

DrainwareSecurityAgent.vcxproj
    Éste es el archivo de proyecto principal para los proyectos de 
    VC++ generados mediante un Asistente para aplicaciones.
    Contiene información acerca de la versión de Visual C++ con la 
    que se generó el archivo, así como información acerca de las 
    plataformas, configuraciones y características del proyecto 
    seleccionadas en el asistente para aplicaciones.

DrainwareSecurityAgent.vcxproj.filters
    Éste es el archivo de filtros para los proyectos de VC++ generados 
    mediante un asistente para aplicaciones. 
    Contiene información acerca de la asociación entre los archivos de 
    un proyecto y los filtros. Esta asociación se usa en el IDE para 
    mostrar la agrupación de archivos con extensiones similares bajo un 
    nodo específico (por ejemplo, los archivos ".cpp" se asocian con el 
    filtro "Archivos de código fuente").

DrainwareSecurityAgent.idl
    Este archivo contiene definiciones IDL de la biblioteca de tipos, las 
    interfaces y las coclases definidas en el proyecto.
    El compilador MIDL procesará este archivo para generar:
        definiciones de la interfaz de C++ 
             y declaraciones                  (DrainwareSecurityAgent.h)
        de GUID                               (DrainwareSecurityAgent_i.c)
        Biblioteca de tipos                   (DrainwareSecurityAgent.tlb)
        Código de cálculo de referencias      (DrainwareSecurityAgent_p.c y 
                                                 dlldata.c)

DrainwareSecurityAgent.h
    Este archivo contiene las definiciones de la interfaz C++ y las 
    declaraciones GUID de los elementos definidos en 
    DrainwareSecurityAgent.idl. MIDL vuelve a generar este archivo durante 
    la compilación.

DrainwareSecurityAgent.cpp
    Este archivo contiene el mapa de objetos y la implementación de WinMain, 
    ServiceMain, y las funciones de administración de servicio.

DrainwareSecurityAgent.rc
    Ésta es una lista de todos los recursos de Microsoft Windows que utiliza 
    el programa.


/////////////////////////////////////////////////////////////////////////////
Otros archivos estándar:

StdAfx.h, StdAfx.cpp
    Estos archivos se utilizan para crear un archivo de encabezado precompilado 
    (PCH) denominado DrainwareSecurityAgent.pch y un archivo de tipos 
    precompilado denominado StdAfx.obj.

Resource.h
    Éste es el archivo de encabezado estándar que define identificadores de 
    recurso.

/////////////////////////////////////////////////////////////////////////////
Proyecto DLL del proxy o código auxiliar y archivo de definición de módulo:

DrainwareSecurityAgentps.vcxproj
    Éste es el archivo de proyecto para generar el archivo DLL del proxy o 
    código auxiliar si es necesario. El archivo IDL del proyecto principal debe 
    contener al menos una interfaz y se debe compilar primero este archivo 
    antes de generar el archivo DLL del proxy o código auxiliar. Este proceso 
    genera dlldata.c, DrainwareSecurityAgent_i.c y DrainwareSecurityAgent_p.c 
    que son necesarios para generar el archivo DLL del proxy o código auxiliar.

DrainwareSecurityAgentps.vcxproj.filters
    Éste es el archivo de filtros para el proyecto proxy/stub. Contiene 
    información acerca de la asociación entre los archivos de un proyecto y los 
    filtros. Esta asociación se usa en el IDE para mostrar la agrupación de 
    archivos con extensiones similares bajo un nodo específico (por ejemplo, 
    los archivos ".cpp" se asocian con el filtro "Archivos de código fuente").

DrainwareSecurityAgentps.def
    Este archivo de definición de módulo proporciona al vinculador información
    acerca de las exportaciones necesarias para el proxy/stub.

/////////////////////////////////////////////////////////////////////////////
