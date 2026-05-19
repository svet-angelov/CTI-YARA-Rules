rule Amadey_Botnet_Payload_And_Memory {
    meta:
        author = "Svetoslav Angelov"
        description = "Detects Amadey botnet payload based on network API imports, dropper behavior, and dynamic C2 extraction."
        date = "2026-05-18"
        malware_family = "Amadey"
        target_entity = "Amadey Command and Control Server"
        hash = "5258a241f8c67e1666060e2c033d127dee8c2c50c7a8dfe0676264e9cb6762c1" 

    strings:
        // --- STATIC INDICATORS ---
        // Removed the 'A' and 'W' suffixes and added wide/nocase to catch all compiler variations
        $net_api1 = "HttpOpenRequest" ascii wide nocase
        $net_api2 = "InternetConnect" ascii wide nocase
        $net_api3 = "HttpAddRequestHeaders" ascii wide nocase

        $drop_api1 = "GetModuleFileName" ascii wide nocase
        $drop_api2 = "CreateProcess" ascii wide nocase

        // --- DYNAMIC INDICATORS (For Memory Dumps) ---
        $c2_ip = "196.251.107.130" ascii wide
        $c2_uri = "/h84jjfAr/index.php" ascii wide

    condition:
        // Ensure it is a Windows executable (MZ header)
        uint16(0) == 0x5A4D and 
        (
            // Trigger 1: Unpacked in memory (The dynamic C2 indicators are visible)
            ($c2_ip and $c2_uri) 
            or
            // Trigger 2: Static file on disk (More flexible threshold for obfuscated APIs)
            (2 of ($net_api*) and any of ($drop_api*))
        )
}
