rule Mal_WIN_RAWorld_Ransomware_PE {
        meta:
                description = "Use to detect RA World ransomware."
                author = "Phatcharadol Thangplub"
                date = "12-26-2025"
                reference = "https://unit42.paloaltonetworks.com/ra-world-ransomware-group-updates-tool-set/"

        strings:
                $s1 = "debug" fullword wide
                $s2 = "shares" fullword wide
                $s3 = "paths" fullword wide
                $s4 = "C:\\Windows\\Help\\Finish.exe" fullword ascii
                $s5 = "C:\\Windows\\Help\\Stage1.exe" fullword ascii
                $s6 = "C:\\Windows\\Help\\Pay.txt" fullword ascii
                $s7 = "Data breach warning.txt" fullword wide
                $s8 = ".YoyVd" fullword wide
                $s9 = ".RAWLD" fullword wide
                $s10 = "For whom the bell tolls, it tolls for thee." fullword ascii
                $s11 = "we are ra world. this is finish" fullword wide

        condition:
                uint16(0) == 0x5A4D and filesize >= 200KB and filesize <= 1MB and (6 of ($s*))

}
