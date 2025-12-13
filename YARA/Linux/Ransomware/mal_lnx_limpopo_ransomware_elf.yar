rule Mal_LNX_Limpopo_Ransomware_ELF {
    meta:
        description = "Use to detect Limpopo ransomware."
        author = "Phatcharadol Thangplub"
        date = "14-02-2025"
        references="https://www.fortinet.com/blog/threat-research/ransomware-roundup-shinra-and-limpopo-ransomware"

    strings:
        $s1 = /(LIMPOPO|limpopo|Limpopo)/
        $s2 = "bsem_init()"
        $s3 = "thread_do()"
        $s4 = "thpool_init()"
        $s5 = "thpool_add_work()"

        /*
            Extension search, and merge directory path.
        */
        $hex1 = { 85 c0 75 ?? 8b 4? ?? 83 c0 0b c7 44 [6] 89 04 ?? e8 [4] 85 c0 
                0f 84 [4] a1 [4] 83 c0 01 a3 [4] 8b 4? ?? 89 44 [2] 8b 4? ?? 89 
                04 ?? e8 }

        /*
            An encrypt function calls in pattern.
        */
        $hex2 = { 0f b6 8? [4] 83 e0 f8 88 8? [4] 0f b6 8? [4] 83 e0 7f 88 8? [4] 
                0f b6 8? [4] 83 c8 40 88 8? [4] c7 44 [6] 8d ?? 90 ec ff ff 89 44 
                [2] 8d ?? 70 ec ff ff 89 04 ?? e8 [4] c7 44 [6] 8d ?? 90 ec ff ff 
                89 44 [2] 8d ?? b0 ec ff ff 89 04 ?? e8 [4] c7 44 [2] 20 00 00 00 
                c7 44 [2] 00 00 00 00 8d ?? 90 ec ff ff 89 04 ?? e8 [4] 8d ?? 50 
                ed ff ff 89 04 ?? e8 [4] c7 44 [2] 20 00 00 00 8d ?? b0 ec ff ff 
                89 44 [2] 8d ?? 50 ed ff ff 89 04 ?? e8 [4] 8d ?? d0 ec ff ff 89 
                44 [2] 8d ?? 50 ed ff ff 89 04 ?? e8 [4] c7 44 [2] 68 00 00 00 c7 
                44 [2] 00 00 00 00 8d ?? 50 ed ff ff 89 04 ?? e8 [4] c7 44 [2] 20 
                00 00 00 8d ?? d0 ec ff ff 89 44 [2] 8d ?? 3c ee ff ff 89 04 ?? e8 
                [4] c7 44 [2] 00 00 00 00 c7 44 [2] 00 00 00 00 8d ?? 3c ee ff ff 
                89 44 [2] 8d ?? b8 ed ff ff 89 04 ?? e8 [4] c7 44 [2] 20 00 00 00 
                c7 44 ?? ?? 00 00 00 00 8d ?? d0 ec ff ff 89 04 ?? e8 }

    condition:
        uint32(0) == 0x464C457F and filesize <= 80KB and (
            ($s1 or ($s1 and $s2 and $s3 and $s4 and $s5)) and all of ($hex*)
        )
}
