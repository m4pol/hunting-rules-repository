rule Mal_WIN_SVC_Stealer_PE {
        meta:
                description = "Use to detect SVCStealer."
                author = "Phatcharadol Thangplub"
                date = "01-28-2026"
                reference = "https://www.seqrite.com/blog/svc-new-stealer-on-the-horizon/"

        strings:
                $s1 = "[Machine]" fullword wide
                $s2 = "[Processes]" fullword wide
                $s3 = "Antivirus:" fullword wide
                $s4 = "qspbhauhcrhn" fullword ascii
                $s5 = "uid=%s&ver=%s&username=%s&cmpname=%s&telegram=%d" fullword ascii
                $s6 = "Content-Disposition: form-data; name=\"log\"; filename=\"%s\"" fullword ascii
                
                /*
                        Concatenating directory path for deletion.
                */
                $hex1 = { 4? 2b d3 0f 1f 00 0f b7 01 66 89 04 0a 4? 8d 49 02 66 85 c0 
                        75 ?? 4? 8d ?? ?4 70 02 00 00 4? 83 e9 02 0f 1f 40 00 66 83 7? 
                        ?? 00 4? 8d ?? 02 75 ?? 8b 05 [4] 89 0? 4? 8d ?? ?4 70 02 00 
                        00 4? 83 e8 02 90 66 83 7? ?? 00 4? 8d ?? 02 75 ?? 4? 8d ?? 
                        ?4 4c 33 d2 0f 1f 40 00 66 66 0f 1f 84 00 00 00 00 00 4? 0f 
                        b7 0c ?? 66 89 0c ?? 4? 8d 52 01 66 85 c9 75 }

        condition:
                uint16(0) == 0x5A4D and filesize >= 80KB and filesize <= 2MB and ((3 of ($s*)) or $hex1)
}