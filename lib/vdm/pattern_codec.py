"""Engine substitution tables shared by VDM signature families."""

from typing import Final

# g_PatternDecodingTable @ 0x180DF1740 in mpengine 1.443.903.0.
PATTERN_DECODING_TABLE: Final = bytes.fromhex(
    "4b ba a3 c0 46 43 84 ed a8 97 3f 72 17 ad ef 54"
    "dd f9 21 64 42 f1 8c 49 68 76 77 fc 11 b2 74 d3"
    "dc 04 09 96 d4 0d f6 19 fb 35 7e 9f d1 e1 9d cc"
    "db 63 f5 30 94 40 7c f3 5d c7 aa e4 e6 14 67 6e"
    "d8 37 a2 b0 56 a6 51 df b9 85 39 15 9e 8d 3e 22"
    "ce fe 7a 0a c1 7d 9c 93 b3 13 08 2a 0c 3d 06 82"
    "60 9b bd 05 c4 24 1e 50 e5 01 4f 1c f4 8a 98 2c"
    "cd 3c 5e 6d 32 8f 2b 47 2f 1d a5 bb 25 b8 d7 b1"
    "65 91 58 c9 be 92 e8 8b 33 55 12 8e ea ab f8 26"
    "1f 71 1b 52 cb e2 e7 86 ae 62 31 fd af 02 d2 0e b7"
    "e3 83 48 16 cf d5 79 03 0f da b5 6f 4d 7b de 07 9a"
    "d9 a0 c8 27 a1 d0 c3 10 bf f7 61 18 eb 38 28 a9 5f"
    "66 c5 0b 95 53 5b 00 f0 7f 81 f2 6a d6 78 73 1a"
    "ac 89 a4 fa 44 36 b4 75 c2 23 bc 59 e9 29 ca 5a 41"
    "6b 34 70 4c ee b6 6c 87 3a 57 80 a7 99 ec 69 ff e0"
    "c6 4a 3b 4e 20 5c 2d 45 88 2e 90"
)

# g_PatternDecodingTableKeepNull @ 0x180E447B0.  It is the normal table
# with mappings at encoded indices 0x00 and 0xC9 exchanged, so NUL survives.
_keep_null = bytearray(PATTERN_DECODING_TABLE)
_keep_null[0x00], _keep_null[0xC9] = _keep_null[0xC9], _keep_null[0x00]
PATTERN_DECODING_TABLE_KEEP_NULL: Final = bytes(_keep_null)
del _keep_null
