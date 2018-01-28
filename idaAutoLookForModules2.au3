
While True
    $win = WinWait("[REGEXPTITLE:(?i)Choose PDB file]")
	;Send("{ENTER}")
    WinClose($win)
Wend