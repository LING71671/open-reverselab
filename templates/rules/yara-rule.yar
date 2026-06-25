rule SampleDetection {
    meta:
        description = "Description of the detection"
        author = ""
        date = ""
        hash = ""
        severity = "low / medium / high / critical"

    strings:
        $str1 = "suspicious string" ascii wide
        $str2 = { 01 02 03 04 05 06 07 08 }
        $regex = /regex pattern/

    condition:
        any of them
}
