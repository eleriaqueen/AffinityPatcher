#!/usr/bin/env python3
"""
Verify the AffinityPatcher analytics signature against a given libacs.dll.

Re-run this on every Affinity update BEFORE shipping patches.json: the pattern
must match exactly once, and must land on the entry of
  Affinity::CloudServices::Analytics::Emitter::DispatchSnowplowSelfDescribingEvent

Usage:  python verify_patch.py "C:\\path\\to\\App\\libacs.dll"
Exit 0 = safe to ship. Exit 1 = re-derive the signature.
"""
import re
import sys
import hashlib

try:
    import pefile
except ImportError:
    sys.exit("pefile required:  python -m pip install pefile")

PATTERN = (
    "48 89 5C 24 20 55 56 57 41 54 41 55 41 56 41 57 "
    "48 8D 6C 24 F0 48 81 EC ? ? ? ? "
    "48 8B 05 ? ? ? ? 48 33 C4 48 89 45 ? "
    "44 89 4C 24 50 49 8B C0 48 89 44 24 60 89 54 24 58 48 8B F9"
)
EXPORT = ("?DispatchSnowplowSelfDescribingEvent@Emitter@Analytics@CloudServices"
          "@Affinity@@IEAAXW4AppIdentifier@34@")


def pat_to_regex(pat):
    out = b""
    for tok in pat.split():
        out += b"." if tok == "?" else re.escape(bytes([int(tok, 16)]))
    return re.compile(out, re.S)


def main(path):
    data = open(path, "rb").read()
    print(f"file   : {path}")
    print(f"size   : {len(data)}")
    print(f"sha256 : {hashlib.sha256(data).hexdigest()}")

    pe = pefile.PE(path, fast_load=True)
    pe.parse_data_directories()
    ib = pe.OPTIONAL_HEADER.ImageBase

    # Ground truth: the real address of the emit funnel, from the export table.
    target_va = None
    for e in getattr(pe.DIRECTORY_ENTRY_EXPORT, "symbols", []):
        if e.name and e.name.decode("utf8", "replace").startswith(EXPORT):
            target_va = ib + e.address
            break
    if target_va is None:
        print("FAIL: DispatchSnowplowSelfDescribingEvent not found in exports.")
        print("      Serif may have renamed/inlined it - re-analyse.")
        return 1
    print(f"target : DispatchSnowplowSelfDescribingEvent @ 0x{target_va:x}")

    text = next(s for s in pe.sections if s.Name.startswith(b".text"))

    def f2va(off):
        return ib + text.VirtualAddress + (off - text.PointerToRawData)

    hits = [m.start() for m in pat_to_regex(PATTERN).finditer(data)]
    print(f"matches: {len(hits)} (need exactly 1)")
    for h in hits:
        va = f2va(h)
        ok = "OK" if va == target_va else "WRONG FUNCTION"
        print(f"   file=0x{h:06x}  VA=0x{va:x}  [{ok}]")

    if len(hits) != 1:
        print("\nFAIL: pattern is not unique -> would trip max_matches and "
              "terminate the process. Re-derive.")
        return 1
    if f2va(hits[0]) != target_va:
        print("\nFAIL: pattern matches the wrong function. Re-derive.")
        return 1
    if data[hits[0]] == 0xC3:
        print("\nNOTE: first byte is already 0xC3 - this file looks "
              "already patched on disk.")
    print("\nPASS: signature is unique and lands on the emit funnel entry. "
          "Safe to ship.")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    sys.exit(main(sys.argv[1]))
