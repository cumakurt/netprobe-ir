/* Example YARA-X rules. These are demonstration rules, not a malware corpus. */
rule NetProbe_EICAR_Demo {
  meta:
    description = "Demonstration detection for the EICAR test string"
    severity = "test"
  strings:
    $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
  condition:
    $eicar
}

rule Suspicious_PE_MZ_HighEntropy_Demo {
  meta:
    description = "Simple PE-header demonstration rule"
  strings:
    $mz = { 4D 5A }
  condition:
    $mz at 0 and filesize < 32MB
}
