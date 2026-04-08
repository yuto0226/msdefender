# Microsoft Defender

Download `mpam-fe.exe` from the Microsoft Security Intelligence updates page.

> <https://www.microsoft.com/en-us/wdsi/defenderupdates>

Then extract its contents with cabextract.

```shell-session
$ cabextract ./mpam-fe.exe
Extracting cabinet: ./mpam-fe.exe
  extracting mpengine.dll
  extracting MpSigStub.exe
  extracting mpasbase.vdm
  extracting mpasdlta.vdm
  extracting mpavbase.vdm
  extracting mpavdlta.vdm
```

## Signatures

Use extractsig.py to extract all signatures from the .vdm files.

```bash
uv run .\extractsig.py .\bin\1.447.226.0\mpasbase.vdm .\bin\1.447.226.0\mpasdlta.vdm
uv run .\extractsig.py .\bin\1.447.226.0\mpavbase.vdm .\bin\1.447.226.0\mpavdlta.vdm
```

Run sigstats.py to view the statistics.

```shell-session
$ uv run .\sigstats.py mpav.sig --top 10
[i] mpav.sig: 3527409 records, 62 unique types

[mpav.sig]
total records: 3,527,409
──────────────────────────────────────────────────────────────────────────────────
  TYPE              COUNT     PCT  BAR
──────────────────────────────────────────────────────────────────────────────────
  STATIC        1,940,504   55.0%  ████████████████████████████████████████ 0x67
  THREAT_BEGIN    342,609    9.7%  ███████ 0x5C
  THREAT_END      342,609    9.7%  ███████ 0x5D
  KCRCE           330,369    9.4%  ███████ 0x80
  SNID            125,242    3.6%  ███ 0x7E
  PEHSTR_EXT       68,440    1.9%  █ 0x78
  PESTATIC         67,187    1.9%  █ 0x87
  NID              58,136    1.6%  █ 0x55
  VERSIONCHECK     41,710    1.2%  █ 0x7A
  NSCRIPT_SP       34,763    1.0%  █ 0x28
──────────────────────────────────────────────────────────────────────────────────
  … 52 more types, 175,840 records (5.0%)
```
