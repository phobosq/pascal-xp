# Ghidra headless: trace FECS callback registration descriptors (XP x64 / Win7 x64).
# -postScript ExportFecsRegistrationOwners.py <out.json> <xp|win7>
# Only static references. Descriptor proximity is NOT proof of GP106 selection.
import json

TARGETS = {
    "xp": ["000eecd0", "000eed10", "000eed50", "000eeec0", "000eef00", "000eef40"],
    "win7": ["0093c7ac", "0093d360", "009432cc", "00943dd0"],
}
MAX_REFS = 48
WINDOW_BEFORE = 0x80
WINDOW_AFTER = 0x100

space = currentProgram.getAddressFactory().getDefaultAddressSpace()
mem = currentProgram.getMemory()

def addr(x):
    return space.getAddress(int(x, 16) if isinstance(x, str) else x)

def section(a):
    block = mem.getBlock(a)
    return block.getName() if block is not None else None

def xrefs(a):
    result = []
    for ref in getReferencesTo(a):
        src = ref.getFromAddress()
        fn = getFunctionContaining(src)
        result.append({"from": str(src), "type": str(ref.getReferenceType()),
                       "section": section(src),
                       "owner": str(fn.getEntryPoint()) if fn else None})
        if len(result) >= MAX_REFS:
            break
    return result

def ptr_at(a):
    try:
        value = int(mem.getLong(a)) & 0xffffffffffffffff
        if value == 0:
            return {"address": str(a), "value": "0x0"}
        dest = addr(value)
        block = mem.getBlock(dest)
        fn = getFunctionAt(dest) if block is not None else None
        if block is None and value > 0xffffffff:
            return None
        return {"address": str(a), "value": "0x%x" % value,
                "target_section": section(dest) if block else None,
                "target_function": str(fn.getEntryPoint()) if fn else None}
    except Exception:
        return None

def descriptor_window(site):
    result = []
    start = int(site.getOffset()) - WINDOW_BEFORE
    end = int(site.getOffset()) + WINDOW_AFTER
    for off in range(start, end + 1, 8):
        a = addr(off)
        if section(a) != section(site):
            continue
        item = ptr_at(a)
        if item is None:
            continue
        refs = xrefs(a)
        if item.get("target_section") or refs or abs(off - int(site.getOffset())) <= 0x40:
            item["relative"] = off - int(site.getOffset())
            if refs:
                item["incoming_refs"] = refs
            result.append(item)
    return result

args = getScriptArgs()
if len(args) != 2 or args[1] not in TARGETS:
    raise ValueError("Expected <out.json> <xp|win7>")
out_path, platform = args
report = {"schema_version": 1, "platform": platform,
          "caveat": "Static DATA refs may include .pdata unwind metadata; exclude those from ownership inference. No runtime GP106 selection is established.",
          "consumers": []}
for entry in TARGETS[platform]:
    fn = getFunctionAt(addr(entry))
    if fn is None:
        report["consumers"].append({"entry": entry, "missing": True})
        continue
    refs = xrefs(fn.getEntryPoint())
    data_sites = sorted(set(r["from"] for r in refs if r["section"] != ".pdata" and r["owner"] is None))
    sites = []
    for site_str in data_sites:
        site = addr(site_str)
        sites.append({"address": site_str, "section": section(site),
                      "window": descriptor_window(site)})
    report["consumers"].append({"entry": entry, "name": fn.getName(),
                                "references": refs, "data_sites": sites})
with open(out_path, "w") as f:
    json.dump(report, f, indent=2)
print("FECS registration owners exported: %s (%d consumers)" % (platform, len(report["consumers"])))
