rule AsyncRAT_Dropper_MSTeams_Campaign {
    meta:
        author = "Svetoslav Angelov"
        description = "Detects an AsyncRAT dropper variant utilising a flawed MSTeamsSetup execution chain and UAC bypass."
        date = "2026-05-30"
        hash = "c3693a465b935ce368769f456942fba955512cf77a421db5bda2a5f4edbd117e"
    strings:
        // Command line execution flags seen in process memory
        $cmd1 = "-el -s2" ascii wide
        $cmd2 = "\"-sp\"" ascii wide
        
        // Campaign-specific payload names
        $file1 = "MSTeamsSetup.exe" ascii wide
        $file2 = "MSTeamsSetup-x64.exe" ascii wide
        $file3 = "sefting.exe" ascii wide
        
    condition:
        // Must be a Windows Executable (MZ header) AND contain at least 3 of our unique strings
        uint16(0) == 0x5A4D and 3 of ($cmd*, $file*)
}
