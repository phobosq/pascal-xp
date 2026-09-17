# Ghidra/PyGhidra script: export detailed facts for functions around Pascal/RM terms.
# Usage:
#   -postScript ExportInterestingFunctionDetails.py <output.json>

from java.io import FileWriter
from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.scalar import Scalar
import json

INTERESTING_TERMS = [
    "GP106", "GP104", "GP102", "PASCAL", "FECS", "GPCCS", "ACR",
    "FALCON", "PMU", "SEC2", "PGRAPH", "PFIFO", "MMU", "CTXSW",
    "UCODE", "FIRMWARE", "HUBCLIENT", "GPCCLIENT", "FBPTE", "PTE", "PDE"
]

MAX_FUNCTIONS = 240
MAX_DECOMP_CHARS = 30000
MAX_INSTRUCTIONS_PER_FUNCTION = 6000


def addr(x):
    return str(x) if x is not None else None


def function_at_or_containing(a):
    f = getFunctionAt(a)
    if f is None:
        f = getFunctionContaining(a)
    return f


def add_fn(selected, reasons, fn, reason):
    if fn is None or fn.isExternal():
        return
    key = addr(fn.getEntryPoint())
    selected[key] = fn
    reasons.setdefault(key, [])
    if reason not in reasons[key]:
        reasons[key].append(reason)


def seed_from_interesting_strings(selected, reasons):
    listing = currentProgram.getListing()
    it = listing.getDefinedData(True)
    while it.hasNext():
        d = it.next()
        try:
            if not d.hasStringValue():
                continue
            value = d.getValue()
            if value is None:
                continue
            text = str(value)
            upper = text.upper()
            hits = [t for t in INTERESTING_TERMS if t in upper]
            if not hits:
                continue
            for r in getReferencesTo(d.getAddress()):
                fn = function_at_or_containing(r.getFromAddress())
                if fn is not None:
                    add_fn(selected, reasons, fn, "string:%s:%s" % (",".join(hits), text[:180]))
        except:
            pass


def expand_neighbors(selected, reasons):
    initial = list(selected.values())
    for fn in initial:
        src_key = addr(fn.getEntryPoint())
        body = fn.getBody()
        ait = body.getAddresses(True)
        while ait.hasNext():
            a = ait.next()
            for r in getReferencesFrom(a):
                try:
                    if r.getReferenceType().isCall():
                        target = function_at_or_containing(r.getToAddress())
                        if target is not None:
                            add_fn(selected, reasons, target, "callee-of:%s" % src_key)
                except:
                    pass
        for r in getReferencesTo(fn.getEntryPoint()):
            try:
                caller = function_at_or_containing(r.getFromAddress())
                if caller is not None:
                    add_fn(selected, reasons, caller, "caller-of:%s" % src_key)
            except:
                pass


def instruction_records(fn):
    out = []
    listing = currentProgram.getListing()
    it = listing.getInstructions(fn.getBody(), True)
    count = 0
    while it.hasNext() and count < MAX_INSTRUCTIONS_PER_FUNCTION:
        insn = it.next()
        scalars = []
        for op_index in range(insn.getNumOperands()):
            for obj in insn.getOpObjects(op_index):
                if isinstance(obj, Scalar):
                    try:
                        scalars.append({
                            "operand": op_index,
                            "value": obj.getValue(),
                            "unsigned": obj.getUnsignedValue(),
                            "bit_length": obj.bitLength(),
                        })
                    except:
                        pass
        refs = []
        for r in getReferencesFrom(insn.getAddress()):
            try:
                refs.append({
                    "to": addr(r.getToAddress()),
                    "type": str(r.getReferenceType()),
                })
            except:
                pass
        out.append({
            "address": addr(insn.getAddress()),
            "mnemonic": insn.getMnemonicString(),
            "text": str(insn),
            "scalars": scalars,
            "refs": refs,
        })
        count += 1
    return out


def call_records(fn):
    out = []
    seen = set()
    body = fn.getBody()
    ait = body.getAddresses(True)
    while ait.hasNext():
        a = ait.next()
        for r in getReferencesFrom(a):
            try:
                if not r.getReferenceType().isCall():
                    continue
                target = function_at_or_containing(r.getToAddress())
                rec = {
                    "from": addr(a),
                    "to": addr(r.getToAddress()),
                    "target_name": target.getName() if target else None,
                    "target_entry": addr(target.getEntryPoint()) if target else None,
                }
                key = (rec["from"], rec["to"])
                if key not in seen:
                    seen.add(key)
                    out.append(rec)
            except:
                pass
    return out


def caller_records(fn):
    out = []
    seen = set()
    for r in getReferencesTo(fn.getEntryPoint()):
        try:
            caller = function_at_or_containing(r.getFromAddress())
            if caller is None:
                continue
            rec = {
                "from": addr(r.getFromAddress()),
                "caller_name": caller.getName(),
                "caller_entry": addr(caller.getEntryPoint()),
            }
            key = (rec["from"], rec["caller_entry"])
            if key not in seen:
                seen.add(key)
                out.append(rec)
        except:
            pass
    return out


def decompile(decompiler, fn):
    try:
        result = decompiler.decompileFunction(fn, 60, monitor)
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
        print("usage: ExportInterestingFunctionDetails.py <output.json>")
        return

    selected = {}
    reasons = {}
    seed_from_interesting_strings(selected, reasons)
    expand_neighbors(selected, reasons)

    keys = sorted(selected.keys())[:MAX_FUNCTIONS]

    decompiler = DecompInterface()
    decompiler.openProgram(currentProgram)

    records = []
    try:
        for key in keys:
            fn = selected[key]
            records.append({
                "name": fn.getName(),
                "entry": key,
                "size": fn.getBody().getNumAddresses(),
                "reasons": reasons.get(key, []),
                "callers": caller_records(fn),
                "calls": call_records(fn),
                "instructions": instruction_records(fn),
                "decompilation": decompile(decompiler, fn),
            })
    finally:
        decompiler.dispose()

    obj = {
        "schema_version": 1,
        "program": currentProgram.getName(),
        "interesting_terms": INTERESTING_TERMS,
        "selected_count": len(keys),
        "selection_count_before_limit": len(selected),
        "max_functions": MAX_FUNCTIONS,
        "functions": records,
    }

    fw = FileWriter(args[0])
    try:
        fw.write(json.dumps(obj, indent=2, sort_keys=True))
    finally:
        fw.close()
    print("Exported %d interesting function records to %s" % (len(records), args[0]))

main()
