rule Gamaredon_Remote_Template_Injection_v2 {
    meta:
        author = "Svetoslav Angelov"
        description = "Aggressive detection for Gamaredon template injection infrastructure"
        date = "2026-06-13"
    strings:
        // Hunt for the template attachment property (case-insensitive)
        $rel = "attachedTemplate" ascii wide nocase
        
        // Hunt for the specific target domain or TLD pattern
        $domain = "freebsdo.ru" ascii wide nocase
        $tld = ".ru" ascii wide nocase
        
        // Hunt for the unique extension used by this campaign
        $ext = ".p3l" ascii wide nocase

    condition:
        // Fire if we find the relationship properties AND the infrastructure clues
        $rel and ($domain or ($tld and $ext))
}
