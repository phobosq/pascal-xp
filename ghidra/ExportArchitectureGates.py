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
PASCAL_FAMILY_VALUES = set([0x130, 0x132, 0x134, 0x136, 0x137, 0x138])
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
        interesting = []
        for op_index in range(insn.getNumOperands()):
            vals = scalar_values_for_operand(insn, op_index)
            for v in vals:
                if v in TARGET_VALUES:
                    interesting.append((op_index, v))
        if not interesting:
            continue
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


def callers(fn):
    out = []
    seen = set()
    for r in getReferencesTo(fn.getEntryPoint()):
        try:
            if not r.getReferenceType().isCall():
                continue
            caller = containing_function(r.getFromAddress())
            item = {
                "from": addr(r.getFromAddress()),
                "caller_entry": addr(caller.getEntryPoint()) if caller else None,
                "caller_name": caller.getName() if caller else None,
                "type": str(r.getReferenceType()),
            }
            k = (item["from"], item["caller_entry"])
            if k not in seen:
                seen.add(k)
                out.append(item)
        except:
            pass
    return out


def instruction_context(a, radius=4):
    listing = currentProgram.getListing()
    center = listing.getInstructionContaining(a)
    if center is None:
        center = listing.getInstructionAt(a)
    if center is None:
        return []
    before = []
    cur = center
    for _ in range(radius):
        cur = listing.getInstructionBefore(cur.getAddress())
        if cur is None:
            break
        before.append(cur)
    before.reverse()
    items = before + [center]
    cur = center
    for _ in range(radius):
        cur = listing.getInstructionAfter(cur.getAddress())
        if cur is None:
            break
        items.append(cur)
    return [{
        "address": addr(insn.getAddress()),
        "text": str(insn),
        "is_reference_source": insn.getAddress() == center.getAddress(),
    } for insn in items]


def reference_record(r):
    source = r.getFromAddress()
    owner = containing_function(source)
    return {
        "from": addr(source),
        "to": addr(r.getToAddress()),
        "type": str(r.getReferenceType()),
        "source": str(r.getSource()),
        "is_primary": bool(r.isPrimary()),
        "owner_entry": addr(owner.getEntryPoint()) if owner else None,
        "owner_name": owner.getName() if owner else None,
    }


def refs_to(a, limit=256):
    out = []
    for r in getReferencesTo(a):
        if len(out) >= limit:
            break
        try:
            out.append(reference_record(r))
        except:
            pass
    return out


def data_context(a):
    data = currentProgram.getListing().getDataContaining(a)
    if data is None:
        return None
    try:
        value = str(data.getValue())
    except:
        value = None
    return {
        "min_address": addr(data.getMinAddress()),
        "max_address": addr(data.getMaxAddress()),
        "length": data.getLength(),
        "data_type": str(data.getDataType()),
        "representation": data.getDefaultValueRepresentation(),
        "value": value,
    }


def indirect_incoming_refs(fn):
    """Export non-call xrefs and one extra xref hop through data/vtable slots."""
    out = []
    seen = set()
    for r in getReferencesTo(fn.getEntryPoint()):
        try:
            source = r.getFromAddress()
            key = (addr(source), str(r.getReferenceType()))
            if key in seen:
                continue
            seen.add(key)
            data = data_context(source)
            anchors = [source]
            if data is not None:
                data_start = currentProgram.getAddressFactory().getAddress(data["min_address"])
                if data_start is not None and data_start != source:
                    anchors.append(data_start)
            second_hop = []
            second_seen = set()
            for anchor in anchors:
                for item in refs_to(anchor):
                    k = (item["from"], item["to"], item["type"])
                    if k not in second_seen:
                        second_seen.add(k)
                        second_hop.append(item)
            item = reference_record(r)
            item["instruction_context"] = instruction_context(source)
            item["data"] = data
            item["refs_to_slot_or_data_start"] = second_hop
            out.append(item)
        except Exception as e:
            out.append({"error": str(e)})
    return out


def is_pascal_family_mapper(rec):
    values = set()
    for hit in rec["hits"]:
        if hit["mnemonic"] not in ("MOV", "MOVZX", "MOVSX"):
            continue
        for item in hit["values"]:
            values.add(item["value"])
    return PASCAL_FAMILY_VALUES.issubset(values)


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
            record = {
                "entry": key,
                "name": fn.getName(),
                "size": fn.getBody().getNumAddresses(),
                "hits": hits[key]["hits"],
                "callers": callers(fn),
                "calls": calls(fn),
                "decompilation": decompile(di, fn),
            }
            record["is_pascal_family_mapper"] = is_pascal_family_mapper(record)
            record["indirect_incoming_refs"] = (
                indirect_incoming_refs(fn) if record["is_pascal_family_mapper"] else []
            )
            records.append(record)
    finally:
        di.dispose()

    obj = {
        "schema_version": 3,
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
