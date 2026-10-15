# Ghidra headless: find candidate writers to FECS/GR callback slots.
# Usage: -postScript ExportFecsSlotAssignments.py <output.json> <xp|win7>
# An offset match is NOT proof of FECS object identity: register bases are untyped.
import json
from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.lang import OperandType
from ghidra.program.model.pcode import PcodeOp
from ghidra.program.model.scalar import Scalar

SLOTS = (0x190, 0x1c8, 0x1d8, 0x1e8, 0x1f8)
MAX_SITES_PER_FUNCTION = 30
MAX_SELECTED_FUNCTIONS = 30
MAX_CALLERS = 24
MAX_DECOMP_CHARS = 25000

def context(address, radius=4):
    listing = currentProgram.getListing()
    cur = listing.getInstructionContaining(address)
    if cur is None:
        return []
    before = []
    for _ in range(radius):
        prev = listing.getInstructionBefore(cur.getAddress())
        if prev is None:
            break
        before.append(prev)
        cur = prev
    before.reverse()
    cur = listing.getInstructionContaining(address)
    out = before + [cur]
    for _ in range(radius):
        nxt = listing.getInstructionAfter(cur.getAddress())
        if nxt is None:
            break
        out.append(nxt)
        cur = nxt
    return [{"address": str(i.getAddress()), "text": str(i)} for i in out]

def slot_operands(insn):
    found = []
    for n in range(insn.getNumOperands()):
        rep = insn.getDefaultOperandRepresentation(n)
        if rep is None or "[" not in rep:
            continue
        values = set()
        for obj in insn.getOpObjects(n):
            if isinstance(obj, Scalar):
                values.add(int(obj.getUnsignedValue()))
        for offset in SLOTS:
            if offset in values:
                flags = insn.getOperandType(n)
                # OperandType.doesWrite() is not reliable for x86 memory operands:
                # Ghidra may report MOV [base+disp],src as read-only. Inspect
                # the instruction's p-code STORE instead, excluding instructions
                # whose implicit stack writes are unrelated to the operand.
                mnemonic = insn.getMnemonicString().upper()
                if mnemonic == "LEA":
                    access = "address"
                elif mnemonic.startswith(("CALL", "PUSH", "ENTER")):
                    access = "read"
                elif any(op.getOpcode() == PcodeOp.STORE for op in insn.getPcode()):
                    access = "write"
                else:
                    access = "write" if OperandType.doesWrite(flags) else "read"
                found.append({"offset": "0x%x" % offset, "operand": n,
                              "operand_text": str(rep), "access": access})
    return found

def callers(fn):
    out = []
    for r in getReferencesTo(fn.getEntryPoint()):
        if not r.getReferenceType().isCall():
            continue
        parent = getFunctionContaining(r.getFromAddress())
        if parent is not None and not parent.isExternal():
            out.append({"site": str(r.getFromAddress()), "function": str(parent.getEntryPoint())})
            if len(out) >= MAX_CALLERS:
                break
    return out

args = getScriptArgs()
if len(args) != 2 or args[1] not in ("xp", "win7"):
    raise ValueError("expected <output.json> <xp|win7>")
out_path, platform = args
listing = currentProgram.getListing()
by_function = {}
it = listing.getInstructions(True)
while it.hasNext():
    insn = it.next()
    hits = slot_operands(insn)
    if not hits:
        continue
    fn = getFunctionContaining(insn.getAddress())
    if fn is None or fn.isExternal():
        continue
    entry = str(fn.getEntryPoint())
    item = by_function.setdefault(entry, {"fn": fn, "writes": 0, "reads": 0,
                                           "addresses": 0, "slots": set(), "sites": []})
    for h in hits:
        item["slots"].add(h["offset"])
        if h["access"] == "write":
            item["writes"] += 1
        elif h["access"] == "read":
            item["reads"] += 1
        else:
            item["addresses"] += 1
    if len(item["sites"]) < MAX_SITES_PER_FUNCTION:
        item["sites"].append({"site": str(insn.getAddress()), "instruction": str(insn),
                              "matches": hits, "context": context(insn.getAddress(), 3)})

# Prefer functions that actually write callback slots, especially multiple distinct slots.
ranked = sorted(by_function.values(),
                key=lambda x: (-len(x["slots"]) if x["writes"] else 0,
                               -x["writes"], -len(x["slots"]), -x["reads"],
                               str(x["fn"].getEntryPoint())))
dec = DecompInterface()
dec.openProgram(currentProgram)
selected = []
for item in ranked[:MAX_SELECTED_FUNCTIONS]:
    fn = item["fn"]
    result = dec.decompileFunction(fn, 90, monitor)
    d = result.getDecompiledFunction() if result.decompileCompleted() else None
    code = str(d.getC()) if d else None
    selected.append({"entry": str(fn.getEntryPoint()), "name": fn.getName(),
                     "size": int(fn.getBody().getNumAddresses()),
                     "writes": item["writes"], "reads": item["reads"],
                     "address_calculations": item["addresses"],
                     "slots": sorted(item["slots"]), "sites": item["sites"],
                     "callers": callers(fn),
                     "decompilation": code[:MAX_DECOMP_CHARS] if code else None,
                     "decompilation_truncated": bool(code and len(code)>MAX_DECOMP_CHARS)})
summary = []
for item in ranked:
    summary.append({"entry": str(item["fn"].getEntryPoint()), "writes": item["writes"],
                    "reads": item["reads"], "slots": sorted(item["slots"])})
report = {"schema_version": 1, "platform": platform,
          "slots": ["0x%x" % x for x in SLOTS],
          "caveat": "Offset-based matches are candidates, not verified FECS object constructors.",
          "total_matching_functions": len(ranked), "summary": summary,
          "selected_functions": selected}
with open(out_path, "w") as f:
    json.dump(report, f, indent=2)
dec.dispose()
print("FECS slot assignment candidates: %s %d functions; %d detailed" %
      (platform, len(ranked), len(selected)))
