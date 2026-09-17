# Ghidra/PyGhidra script: find likely Maxwell/Pascal chipset/PCI-ID gates.
# Usage: -postScript ExportArchitectureGates.py <output.json>

from java.io import FileWriter
from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.scalar import Scalar
import json

# Nouveau/NVIDIA-style chipset identifiers commonly encountered in RM code:
# GM200/204/206 = 0x120/0x124/0x126; GP100/102/104/106/107/108 =
# 0x130/0x132/0x134/0x136/0x137/0x138. 0x12f is useful as a range boundary.
CHIPSET_VALUES = set([0x120, 0x124, 0x126, 0x12f, 0x130, 0x132, 0x134, 0x136, 0x137, 0x138])
PCI_VALUES = set([0x1c03])  # common GTX 1060 6GB device ID
TARGET_VALUES = CHIPSET_VALUES | PCI_VALUES
MAX_DECOMP_CHARS = 50000


def addr(x):
    return str(x) if x is not None else None


def containing_function(a):
    fn = getFunctionContaining(a)
    if fn is None:
        fn = getFunctionAt(a)
    return fn


def scalar_values_for_operand(insn, op_index):
    out = []
    for obj in insn.getOpObjects(op_index):
        if isinstance(obj, Scalar):
            try:
                out.append(int(obj.getUnsignedValue()))
            except:
                pass
    return out


def find_gates():
    listing = currentProgram.getListing()
    it = listing.getInstructions(True)
    hits = {}
    while it.hasNext():
        insn = it.next()
        mnemonic = insn.getMnemonicString().upper()
        # Immediate-generation checks are most useful when the interesting value
        # is the RHS of CMP/SUB or an immediate loaded into a register/table.
        interesting = []
        for op_index in range(insn.getNumOperands()):
            vals = scalar_values_for_operand(insn, op_index)
            for v in vals:
                if v in TARGET_VALUES:
                    interesting.append((op_index, v))
        if not interesting:
            continue
        # Avoid drowning in structure offsets: for CMP/SUB require the value in
        # a non-first operand. For MOV/LEA/etc retain only explicit second-op hits.
        filtered = []
        for op_index, v in interesting:
            if mnemonic in ("CMP", "SUB"):
                if op_index >= 1:
                    filtered.append((op_index, v))
            elif mnemonic in ("MOV", "MOVZX", "MOVSX", "AND", "OR", "XOR"):
                if op_index >= 1:
                    filtered.append((op_index, v))
        if not filtered:
            continue
        fn = containing_function(insn.getAddress())
        if fn is None or fn.isExternal():
            continue
        key = addr(fn.getEntryPoint())
        rec = hits.setdefault(key, {
            "function": fn,
            "hits": [],
        })
        rec["hits"].append({
            "address": addr(insn.getAddress()),
            "mnemonic": mnemonic,
            "text": str(insn),
            "values": [{"operand": op, "value": v, "hex": "0x%x" % v} for op, v in filtered],
        })
    return hits


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
                k = (item["from"], item["to"])
                if k not in seen:
                    seen.add(k)
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
        print("usage: ExportArchitectureGates.py <output.json>")
        return

    hits = find_gates()
    di = DecompInterface()
    di.openProgram(currentProgram)
    records = []
    try:
        for key in sorted(hits.keys()):
            fn = hits[key]["function"]
            records.append({
                "entry": key,
                "name": fn.getName(),
                "size": fn.getBody().getNumAddresses(),
                "hits": hits[key]["hits"],
                "calls": calls(fn),
                "decompilation": decompile(di, fn),
            })
    finally:
        di.dispose()

    obj = {
        "schema_version": 1,
        "program": currentProgram.getName(),
        "chipset_values": ["0x%x" % v for v in sorted(CHIPSET_VALUES)],
        "pci_values": ["0x%x" % v for v in sorted(PCI_VALUES)],
        "function_count": len(records),
        "functions": records,
    }
    fw = FileWriter(args[0])
    try:
        fw.write(json.dumps(obj, indent=2, sort_keys=True))
    finally:
        fw.close()
    print("Exported %d architecture-gate functions to %s" % (len(records), args[0]))

main()
