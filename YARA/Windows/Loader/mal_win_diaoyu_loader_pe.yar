rule Mal_WIN_Diaoyu_Loader_PE {
        meta:
                description = "Use to detect Diaoyu Loader."
                author = "Phatcharadol Thangplub"
                date = "02-22-2026"
                reference = "https://unit42.paloaltonetworks.com/shadow-campaigns-uncovering-global-espionage/"

        strings:
                $s1 = "DiaoYu.exe" fullword wide
                $s2 = "05343A1E2A3B3B212C201505463E3503051C" fullword ascii
                $s3 = "urlmon.dll" fullword ascii
                $s4 = "avp.exe" fullword ascii
                $s5 = "SentryEye.exe" fullword ascii
                $s6 = "EPSecurityService.exe" fullword ascii
                $s7 = "SentinelUI.exe" fullword ascii
                $s8 = "NortonSecurity.exe" fullword ascii
                
                /*
                        Decrypt hard-coded strings.
                */
                $hex1 = { 4? 33 ed 4? 89 7c [2] 4? 63 f5 85 ed 7e ?? 4? 89 74 [2] 4? 89 
                        7c [2] 4? 8b fd 90 4? 0f be 0c 7c 4? 0f be 7c 7c 01 e8 [4] 2c 
                        30 8b cf 0f b6 f0 e8 [4] 2c 30 4? 0f b6 c0 4? 80 fe 09 8d 46 
                        f9 0f b6 d0 0f 4e d6 c0 e2 04 4? 8d 40 f9 4? 80 f8 09 0f b6 
                        c8 4? 0f 4e c8 02 d1 4? 88 14 1f 4? ff c7 4? 3b fe 7c ?? 4? 
                        8b 7c [2] 4? 8b 74 [2] 4? 8b 64 [2] 4? 8d 15 [4] 85 ed 0f 8e [4] 
                        83 fd 40 0f 82 [4] 8d 45 ff 4? 63 c8 4? 8d 04 ?? 4? 8d 04 19 
                        4? 3b d8 77 ?? 4? 3b c2 0f 83 [4] 8b cd 81 e1 3f 00 00 80 7d 
                        ?? ff c9 83 c9 c0 ff c1 8b c5 4? 8d 05 [4] 2b c1 4? 8b fa 4? 
                        8b ca 4? 63 d8 4? 2b fb 4? 8d 4b 20 4? 2b c3 4? 2b cb 4? c7 
                        c2 e0 ff ff ff 4? 2b d3 66 90 f3 0f 6f 41 e0 4? 83 c5 40 f3 
                        0f 6f 4c 0f e0 f3 4? 0f 6f 14 09 4? 8d 49 40 66 0f ef c8 4? 
                        8d 04 0a f3 0f 7f 49 a0 f3 0f 6f 41 b0 f3 4? 0f 6f 4c 08 a0 
                        66 0f ef c8 f3 0f 7f 49 b0 f3 0f 6f 41 c0 f3 4? 0f 6f 4c 08 
                        c0 66 0f ef d0 f3 0f 7f 51 c0 f3 0f 6f 41 d0 66 0f ef c8 f3 
                        0f 7f 49 d0 4? 3b c3 7c ?? 4? 8b 7c [2] 4? 63 c5 4? 8b 6c [2] 
                        4? 3b c6 7d ?? 4? 2b d3 4? 8d 0c 18 4? 2b f0 90 0f b6 04 11 
                        30 01 4? 8d 49 01 4? 83 ee 01 75 ?? 4? 8b 74 [2] 4? 63 c5 4? 
                        8b 6c [2] 4? ff c8 4? 85 c0 7e ?? 4? 8b c3 4? 8d 14 18 4? f7 
                        d8 90 0f b6 02 4? 8d 52 ff 0f b6 0b 88 03 4? 8d 5b 01 88 4a 
                        01 4? 8d 04 02 4? 8d 0c 03 4? 3b c8 7c }

                /*
                        Decrypt file content strings.
                */
                $hex2 = { 4? 8d 41 05 ff c1 83 e0 1f 4? 8d 52 01 4? 0f b6 04 ?? 30 42 ff 4? 63 c1 4? 3b c7 72 }

        condition:
                uint16(0) == 0x5A4D and filesize >= 100KB and filesize <= 150KB and 
                (($s1 or ($s2 and $s3)) and ($s4 or $s5 or $s6 or $s7 or $s8) and ($hex1 or $hex2))
}