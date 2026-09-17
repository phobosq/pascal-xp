# Ghidra Jython script
# ExportProgramFacts.py
#
# Usage (headless):
# analyzeHeadless <project_dir> <project_name> -import <binary> \
#   -postScript ExportProgramFacts.py <output.json>

from java.io import FileWriter
import json

INTERESTING_TERMS = [
    "GP106", "GP104", "GP102", "PASCAL", "FECS", "GPCCS", "ACR",
    "FALCON", "PMU", "SEC2", "PGRAPH", "PFIFO", "MMU", "CTXSW",
    "UCODE", "FIRMWARE", "10DE", "1C03"
]


def addr(x):
    return str(x) if x is not None else None


def containing_function(a):
    try:
        f = getFunctionContaining(a)
        if f is None:
            return None
        return {"name": f.getName(), "entry": addr(f.getEntryPoint())}
    except:
        return None


def function_record(fn):
    body = fn.getBody()
    refs_in = 0
    refs_out = 0
    calls = []

    it = body.getAddresses(True)
    while it.hasNext():
        a = it.next()
        refs_in += len(getReferencesTo(a))
        for r in getReferencesFrom(a):
            refs_out += 1
            try:
                if r.getReferenceType().isCall():
                    target = getFunctionAt(r.getToAddress())
                    calls.append({
                        "from": addr(a),
                        "to": addr(r.getToAddress()),
                        "target_name": target.getName() if target else None,
                    })
            except:
                pass

    uniq = []
    seen = set()
    for c in calls:
        key = (c["from"], c["to"])
        if key not in seen:
            seen.add(key)
            uniq.append(c)

    return {
        "name": fn.getName(),
        "entry": addr(fn.getEntryPoint()),
        "size": body.getNumAddresses(),
        "thunk": bool(fn.isThunk()),
        "external": bool(fn.isExternal()),
        "calling_convention": fn.getCallingConventionName(),
        "parameter_count": fn.getParameterCount(),
        "refs_in": refs_in,
        "refs_out": refs_out,
        "calls": uniq,
    }


def export_strings():
    out = []
    listing = currentProgram.getListing()
    data_it = listing.getDefinedData(True)
    while data_it.hasNext():
        d = data_it.next()
        try:
            if not d.hasStringValue():
                continue
            value = d.getValue()
            if value is None:
                continue
            text = str(value)
            refs = []
            for r in getReferencesTo(d.getAddress()):
                refs.append({
                    "from": addr(r.getFromAddress()),
                    "type": str(r.getReferenceType()),
                    "function": containing_function(r.getFromAddress()),
                })
            upper = text.upper()
            terms = [t for t in INTERESTING_TERMS if t in upper]
            out.append({
                "address": addr(d.getAddress()),
                "length": d.getLength(),
                "value": text,
                "xrefs": refs,
                "interesting_terms": terms,
            })
        except:
            pass
    return out


def export_symbols(limit=200000):
    table = currentProgram.getSymbolTable()
    it = table.getAllSymbols(True)
    out = []
    count = 0
    while it.hasNext() and count < limit:
        s = it.next()
        name = s.getName()
        upper = name.upper()
        out.append({
            "name": name,
            "address": addr(s.getAddress()),
            "type": str(s.getSymbolType()),
            "source": str(s.getSource()),
            "interesting_terms": [t for t in INTERESTING_TERMS if t in upper],
        })
        count += 1
    return out


def main():
    args = getScriptArgs()
    if len(args) != 1:
        print("usage: ExportProgramFacts.py <output.json>")
        return

    out_path = args[0]
    fm = currentProgram.getFunctionManager()
    functions = []
    it = fm.getFunctions(True)
    while it.hasNext():
        functions.append(function_record(it.next()))

    memory = currentProgram.getMemory()
    blocks = []
    for b in memory.getBlocks():
        blocks.append({
            "name": b.getName(),
            "start": addr(b.getStart()),
            "end": addr(b.getEnd()),
            "size": b.getSize(),
            "execute": bool(b.isExecute()),
            "read": bool(b.isRead()),
            "write": bool(b.isWrite()),
        })

    obj = {
        "schema_version": 2,
        "program": {
            "name": currentProgram.getName(),
            "language": str(currentProgram.getLanguageID()),
            "compiler": str(currentProgram.getCompilerSpec().getCompilerSpecID()),
            "image_base": addr(currentProgram.getImageBase()),
            "executable_format": currentProgram.getExecutableFormat(),
        },
        "interesting_terms": INTERESTING_TERMS,
        "memory_blocks": blocks,
        "functions": functions,
        "strings": export_strings(),
        "symbols": export_symbols(),
    }

    fw = FileWriter(out_path)
    try:
        fw.write(json.dumps(obj, indent=2, sort_keys=True))
    finally:
        fw.close()

    print("Exported program facts to %s" % out_path)

main()
