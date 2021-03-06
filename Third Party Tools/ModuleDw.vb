Imports System
Imports EnvDTE
Imports EnvDTE80
Imports EnvDTE90
Imports EnvDTE90a
Imports EnvDTE100
Imports System.Diagnostics
Imports System.IO


Public Module ModuleDw
    Public Sub IncBuild()
        Dim strFileName As String
        strFileName = DTE.Solution.FindProjectItem("DseVersion.h").FileNames(1)

        Dim oFile As StreamReader = File.OpenText(strFileName)
        Dim strContent As String

        Do While oFile.Peek() >= 0
            Dim strLine As String = oFile.ReadLine()

            Dim nIndex = strLine.IndexOf("#define DWBUILDVERSION")

            If Not nIndex = -1 Then
                strLine = "#define DWBUILDVERSION " & (CInt(strLine.Substring(22)) + 1).ToString()
            End If

            strContent += strLine

            strContent += Chr(13) & Chr(10)
        Loop

        oFile.Close()

        'MsgBox(strContent)

        Dim oFileW As StreamWriter = File.CreateText(strFileName)
        oFileW.Write(strContent)
        oFileW.Flush()
        oFileW.Close()

    End Sub
End Module
