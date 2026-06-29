rule WSHRAT_Houdini_VBS_Dropper {
    meta:
        author = "CTI Analyst"
        description = "Detects VBScript variant of WSHRAT/Houdini utilizing PowerShell Process Hollowing and Registry storage."
        date = "2026-06-28"
        hash = "207ac97e60aeb989a14feaae8a365f5b35233ac7800f1357b325a0bd8d3bdd5c" 
        threat_actor = "kognito"

    strings:
        // Threat Actor Signatures
        $ta_skype = "skype : live:unknown.sales64" ascii nocase
        $ta_name = "recoder : kognito" ascii nocase

        // Core RAT Strings
        $rat_name = "WSHRAT" ascii fullword
        $c2_domain = "snkcyp.duckdns.org" ascii fullword
        
        // Fileless Execution / Registry Keys
        $reg_plugin = "HKCU\\SOFTWARE\\Microsoft\\mPluginC" ascii nocase
        $reg_runpe = "HKCU\\SOFTWARE\\Microsoft\\mRunPE" ascii nocase
        
        // Obfuscation / Execution methods
        $ps_inject = "powershell -ExecutionPolicy Bypass -windowstyle hidden -Command" ascii nocase
        $ps_reflect = "[System.Reflection.Assembly]::Load([Convert]::FromBase64String(" ascii nocase

    condition:
        // Require either the specific threat actor signature OR a combination of the RAT mechanics
        ( $ta_skype or $ta_name ) or 
        ( $rat_name and $c2_domain ) or 
        ( $reg_plugin and $reg_runpe and $ps_inject and $ps_reflect )
}
