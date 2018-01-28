
While True
    $win = WinWait("[REGEXPTITLE:(?i)Microsoft Internet Symbol Store]")
	;Send("{ENTER}")
    WinClose($win)
Wend