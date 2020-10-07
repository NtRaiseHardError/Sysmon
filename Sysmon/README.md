# Sysmon

## Sysmon-KExec

Execute arbitrary shellcode in the kernel.

Related blog post: https://undev.ninja/sysmon-internals-from-file-delete-event-to-kernel-code-execution/

### Sysmons

Vulnerable versions of Sysmon (version 11.0 - 12.0).

### Impacted Versions

* 11.0
* 11.10
* 11.11
* 12.0

### Known Impacted Hashes

```
35c67ac6cb0ade768ccf11999b9aaf016ab9ae92fb51865d73ec1f7907709dca
d2ed01cce3e7502b1dd8be35abf95e6e8613c5733ee66e749b972542495743b8
a86e063ac5214ebb7e691506a9f877d12b7958e071ecbae0f0723ae24e273a73
c0640d0d9260689b1c6c63a60799e0c8e272067dcf86847c882980913694543a
2a5e73343a38e7b70a04f1b46e9a2dde7ca85f38a4fb2e51e92f252dad7034d4
98660006f0e923030c5c5c8187ad2fe1500f59d32fa4d3286da50709271d0d7f
7e1d7cfe0bdf5f17def755ae668c780dedb027164788b4bb246613e716688840
```

### Yara Signature

```
rule Sysmon_KExec_KPPL {
meta:
 date = "30-09-2020"
 author = "SBousseaden"
 description = "hunt for possible injection with Instrumentation Callback PE"
 reference = "https://undev.ninja/sysmon-internals-from-file-delete-event-to-kernel-code-execution/"
strings:
 $sc1 = {90 51 B9 00 48 8D 0D DB 1F 00 00 44 89 7C 24 48 41 8B F7 4C 89 BD F0 01} 
 $sc2 = {65 C7 85 B8 01 00 00 48 8B 04 25} 
 $sc3 = {C7 85 BC 01 00 00 88 01 00 00 C7 85 C0 01 00}
 $sc4 = {DC 01 00 00 EA C6 80 ?? C7 85 E0 01 00 00 ?? 00 00 00 48}
 $sc5 = {C7 85 E4 01 00 00 48 B8 00 00 C7 85 EC 01 00 00 00 00 48 B9} 
 $sc6 = {48 89 01 59 66 C7 85 FC 01 00 00 FF E0}
 $sc7 = {65 48 8B 04 ?? ?? ?? 25 88 01 00}
 $sc8 = {48 8B 04 25 C7 85 4C 02 00 00 88 01}
 $sc9 = {48 89 01 59 66 C7}
 $ioc1 = {30 45 33 C9 C7 44 24 28 B8 FC 03 00 45 33 C0 BA 04 00 40 83 48 89 5C 24 20 48 8B}
 $ioc2 = {4C 89 74 24 30 BA 10 00 40 83 44 89 74 24 28 48 8B CE 4C 89}
 $sdrv1 = "SysmonDrv" wide
 $sdrv2 = "SysmonDrv"
condition: uint16(0) == 0x5a4d and 1 of ($sdrv*) and (2 of ($sc*) or 1 of ($ioc*))
}
```

## ImageFileName-Evasion

Fake the `ImageFileName` value in some events.

Related blog post: https://undev.ninja/sysmon-image-file-name-evasion/
