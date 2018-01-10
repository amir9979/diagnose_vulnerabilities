
While True
    $win = WinWait("[REGEXPTITLE:(?i)Select file for module]")
	;Send("{ENTER}")
    WinClose($win)
Wend