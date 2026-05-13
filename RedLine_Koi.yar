rule MALWARE_Win_RedLine_KoiVariant {
    meta:
        description = "Detects RedLine Stealer using the Koi Reflective Loader"
        author = "Svetoslav Angelov | Realirar Team"
        reference = "Internal Lab Analysis"
        hash = "f64ccc637b29a4000090e960789f88470ef02eca8b1e063e4b5611a7f43b3961"

    strings:
        $packer = "ConfusedByAttribute" ascii
        $loader = "koi" wide ascii
        $namespace = "Steanings" ascii
        $net_tcp = { 6E 00 65 00 74 00 2E 00 74 00 63 00 70 00 3A 00 2F 00 2F } 

    condition:
        uint16(0) == 0x5A4D and 
        2 of ($packer, $loader, $namespace) or $net_tcp
}