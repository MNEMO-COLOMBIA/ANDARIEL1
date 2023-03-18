rule andariel_malware {
    meta:
        description = "Identifies Andariel malware by searching for specific strings."
        author = "Fevar54"
        reference = "https://www.kaspersky.com/about/press-releases/2022_andariel-a-lazarus-subgroup-expands-its-attacks-with-new-ransomware"
        date = "2023-03-17"
    strings:
        $string1 = "andariel"
        $string2 = "loader"
        $string3 = "dropper"
        $string4 = "backdoor"
        $string5 = "c2"
    condition:
        any of ($string*) in (pe.sections[*].name, pe.imports[*].name, pe.exports[*].name, pe.resources[*].name, pe.rich_signature.clear_data.ascii)
}
