rule Mal_WIN_GhostFetch_Loader_PE {
        meta:
                description = "Use to detect GhostFetch Loader."
                author = "Phatcharadol Thangplub"
                date = "05-15-2026"
                reference = "https://www.group-ib.com/blog/muddywater-operation-olalampo/"

        strings:
                /*
                        Mutex deobfuscation algorithm.
                */
                $hex1 = { 66 89 10 4? ba fb 00 00 00 66 89 48 04 4? bb fd 00 00 00 0f 
                        b7 53 02 0f b7 4b 06 66 4? 2b d1 66 89 50 02 66 83 e9 09 66 89 
                        48 06 ba ff 00 00 00 0f b7 43 08 b9 f9 00 00 00 66 2b c1 66 4? 
                        89 40 08 0f b7 43 0a 66 83 e8 03 66 4? 89 40 0a 0f b7 43 0c 66 
                        4? 2b c1 66 4? 89 40 0c 0f b7 43 0e 66 4? 2b c2 66 4? 89 40 0e 
                        0f b7 43 10 66 83 e8 03 66 4? 89 40 10 0f b7 43 12 66 4? 2b c1 
                        66 4? 89 40 12 0f b7 43 14 66 83 e8 08 66 4? 89 40 14 0f b7 43 
                        16 66 83 e8 03 66 4? 89 40 16 0f b7 43 18 66 2b c1 66 4? 89 40 
                        18 0f b7 43 1a 66 4? 2b c1 66 4? 89 40 1a 0f b7 43 1c 66 4? 2b 
                        c3 66 4? 89 40 1c 0f b7 43 1e 66 83 e8 05 66 4? 89 40 1e 0f b7 
                        43 20 66 2b c2 66 4? 89 40 20 0f b7 43 22 66 4? 2b c3 66 4? 89 
                        40 22 0f b7 43 24 66 2b c2 66 4? 89 40 24 0f b7 43 26 66 83 e8 
                        03 66 4? 89 40 26 0f b7 43 28 66 83 e8 02 66 4? 89 40 28 0f b7 
                        43 2a 66 4? 2b c1 66 4? 89 40 2a 0f b7 43 2c 66 83 e8 09 66 4? 
                        89 40 2c 0f b7 43 2e b9 f7 00 00 00 66 2b c2 66 4? 89 40 2e 0f 
                        b7 43 30 66 2b c1 66 4? 89 40 30 0f b7 43 32 66 83 e8 03 66 4? 
                        89 40 32 0f b7 43 34 66 83 e8 04 66 4? 89 40 34 0f b7 43 36 66 
                        83 e8 04 66 4? 89 40 36 0f b7 43 38 66 83 e8 06 66 4? 89 40 38 
                        0f b7 43 3a 66 4? 2b c3 66 4? 89 40 3a 0f b7 43 3c 66 83 e8 04 
                        66 4? 89 40 3c 0f b7 43 3e 66 83 e8 09 66 4? 89 40 3e 0f b7 43 
                        40 66 83 e8 06 66 4? 89 40 40 0f b7 43 42 66 2b c2 66 4? 89 40 
                        42 0f b7 43 44 66 83 e8 03 66 4? 89 40 44 0f b7 43 46 66 2b c1 
                        b9 fc 00 00 00 66 4? 89 40 46 0f b7 43 48 66 83 e8 06 66 4? 89 
                        40 48 0f b7 43 4a 66 4? 2b c2 66 4? 89 40 4a 0f b7 43 4c 66 83 
                        e8 03 66 4? 89 40 4c 0f b7 43 4e 66 83 e8 09 66 4? 89 40 4e 0f 
                        b7 43 50 66 83 e8 03 66 4? 89 40 50 0f b7 43 52 66 2b c1 b9 fa 
                        00 00 00 66 4? 89 40 52 0f b7 43 54 66 2b c1 b9 f6 00 00 00 66 
                        4? 89 40 54 0f b7 43 56 66 83 e8 06 66 4? 89 40 56 0f b7 43 58 
                        66 83 e8 04 66 4? 89 40 58 0f b7 43 5a 66 83 e8 03 66 4? 89 40 
                        5a 0f b7 43 5c 66 2b c1 66 4? 89 40 5c 0f b7 43 5e 66 83 e8 06 
                        66 4? 89 40 5e 0f b7 43 60 66 4? 2b c3 66 4? 89 40 60 }
                /*
                        Initialize the section of the encryption data scheme.
                */
                $hex2 = { c7 03 01 02 03 04 c7 43 04 05 06 07 08 c7 43 08 09 0a 0b 0c 
                        66 c7 43 0c 0d 0e c6 43 0e 0f }

                /*
                        Creation of the magic constant for the encryption data scheme.
                */
                $hex3 = { 4? 8d 53 0f 4? 8d 4a 0f 4? 8d 40 0f 4? 3b d0 77 ?? 33 c0 4? 
                        3b c8 72 ?? 4? 8d 0c 10 4? 2b c2 ba 10 00 00 00 4? 2b d0 0f 1f 
                        80 00 00 00 00 4? 0f b6 04 01 88 01 4? 8d 49 01 4? 83 ea 01 75 
                        ?? eb ?? 4? 0f 10 00 0f 11 02 }

                /*
                        Manual DOS and NT header resolution and checking.
                */
                $hex4 = { 4? 83 ec 70 4? 8b 05 [4] 4? 33 c4 4? 89 44 [2] b8 4d 5a 00 00 
                        4? 8b f9 66 39 01 0f 85 [4] 4? 63 41 3c 3d 00 04 00 00 0f 8f [4] 
                        81 3c 01 50 45 00 00 4? 89 7? ?? 4? 8d 34 01 0f 85 [4] 4? 85 f6 }

        condition:
                uint16(0) == 0x5A4D and filesize >= 180KB and ($hex1 and (($hex2 and $hex3) or $hex4))
}