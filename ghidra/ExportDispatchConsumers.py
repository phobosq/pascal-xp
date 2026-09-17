# Ghidra/PyGhidra script: locate consumers of the architecture-mapper slot.
# Usage: -postScript ExportDispatchConsumers.py <output.json>

from java.io import FileWriter
from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.scalar import Scalar
import json

TARGET_OFFSETS = set([0x190])
MAX_DECOMP_CHARS = 50000


def addr(x):
    return str(x) if x is not None else None


def scalar_values(insn):
    out = []
    for op_index in range(insn.getNumOperands()):
        for obj in insn.getOpObjects(op_index):
            if isinstance(obj, Scalar):
                try:
                    out.append({
                        "operand": op_index,
                        "value": int(obj.getUnsignedValue()),
                    })
                except:
                    pass
    return out


def instruction_context(insn, radius=6):
    listing = currentProgram.getListing()
    before = []
    cur = insn
    for _ in range(radius):
        cur = listing.getInstructionBefore(cur.getAddress())
        if cur is None:
            break
        before.append(cur)
    before.reverse()
    items = before + [insn]
    cur = insn
    for _ in range(radius):
        cur = listing.getInstructionAfter(cur.getAddress())
        if cur is None:
            break
        items.append(cur)
    return [{
        "address": addr(item.getAddress()),
        "text": str(item),
        "is_hit": item.getAddress() == insn.getAddress(),
    } for item in items]


def calls(fn):
    out = []
    seen = set()
    it = currentProgram.getListing().getInstructions(fn.getBody(), True)
    while it.hasNext():
        insn = it.next()
        for r in getReferencesFrom(insn.getAddress()):
            try:
                if not r.getReferenceType().isCall():
                    continue
                target = getFunctionAt(r.getToAddress())
                item = {
                    "from": addr(insn.getAddress()),
                    "to": addr(r.getToAddress()),
                    "target_name": target.getName() if target else None,
                }
                key = (item["from"], item["to"])
                if key not in seen:
                    seen.add(key)
                    out.append(item)
            except:
                pass
    return out


def callers(fn):
    out = []
    seen = set()
    for r in getReferencesTo(fn.getEntryPoint()):
        try:
            if not r.getReferenceType().isCall():
                continue
            caller = getFunctionContaining(r.getFromAddress())
            item = {
                "from": addr(r.getFromAddress()),
                "caller_entry": addr(caller.getEntryPoint()) if caller else None,
                "caller_name": caller.getName() if caller else None,
            }
            key = (item["from"], item["caller_entry"])
            if key not in seen:
                seen.add(key)
                out.append(item)
        except:
            pass
    return out


def decompile(di, fn):
    try:
        result = di.decompileFunction(fn, 90, monitor)
        if not result.decompileCompleted():
            return {"ok": False, "error": result.getErrorMessage(), "c": None}
        text = result.getDecompiledFunction().getC()
        if text is not None and len(text) > MAX_DECOMP_CHARS:
            text = text[:MAX_DECOMP_CHARS] + "\n/* truncated */\n"
        return {"ok": True, "error": None, "c": text}
    except Exception as e:
        return {"ok": False, "error": str(e), "c": None}


def main():
    args = getScriptArgs()
    if len(args) != 1:
        print("usage: ExportDispatchConsumers.py <output.json>")
        return

    listing = currentProgram.getListing()
    by_function = {}
    it = listing.getInstructions(True)
    while it.hasNext():
        insn = it.next()
        mnemonic = insn.getMnemonicString().upper()
        if mnemonic not in ("CALL", "JMP", "MOV", "LEA"):
            continue
        scalars = scalar_values(insn)
        matched = [x for x in scalars if x["value"] in TARGET_OFFSETS]
        if not matched:
            continue
        fn = getFunctionContaining(insn.getAddress())
        if fn is None or fn.isExternal():
            continue
        key = addr(fn.getEntryPoint())
        rec = by_function.setdefault(key, {"function": fn, "hits": []})
        rec["hits"].append({
            "address": addr(insn.getAddress()),
            "mnemonic": mnemonic,
            "text": str(insn),
            "matched_scalars": matched,
            "context": instruction_context(insn),
        })

    di = DecompInterface()
    di.openProgram(currentProgram)
    records = []
    try:
        for key in sorted(by_function.keys()):
            fn = by_function[key]["function"]
            records.append({
                "entry": key,
                "name": fn.getName(),
                "size": fn.getBody().getNumAddresses(),
                "hits": by_function[key]["hits"],
                "callers": callers(fn),
                "calls": calls(fn),
                "decompilation": decompile(di, fn),
            })
    finally:
        di.dispose()

    obj = {
        "schema_version": 1,
        "program": currentProgram.getName(),
        "target_offsets": ["0x%x" % x for x in sorted(TARGET_OFFSETS)],
        "function_count": len(records),
        "functions": records,
    }
    fw = FileWriter(args[0])
    try:
        fw.write(json.dumps(obj, indent=2, sort_keys=True))
    finally:
        fw.close()
    print("Exported %d dispatch-consumer functions to %s" % (len(records), args[0]))


main()
