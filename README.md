# Microsoft Defender

## 依版本下載 engine

```powershell
uv run geteng.py list
uv run geteng.py update
uv run geteng.py download 1.443.6.0
uv run geteng.py download 1.447.224.0 1.447.226.0
```

`list` 列出 package、engine 與發布日期；`update` 更新 `defender_version.json`；`download` 保留 `mpam-fe.exe`，並將套件內容解到 `bin/<package>/<arch>/extracted/`。uv 依 inline metadata 處理 Requests、Rich 與 tqdm 相依套件；解包使用 7-Zip 或 cabextract。

## 手動下載

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

Use `extractvdm.py` to extract all signatures from the .vdm files.

```bash
uv run ./extractvdm.py ./bin/1.447.226.0/mpasbase.vdm ./bin/1.447.226.0/mpasdlta.vdm
uv run ./extractvdm.py ./bin/1.447.226.0/mpavbase.vdm ./bin/1.447.226.0/mpavdlta.vdm
```

Run `sigstats.py` to view the statistics.

```shell-session
$ uv run .\sigstats.py mpav.sig --top 10
[*] mpav.sig: 3527409 records, 62 unique types

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
