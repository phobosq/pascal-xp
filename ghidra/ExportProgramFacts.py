# Ghidra Jython script
# ExportProgramFacts.py
#
# Usage (headless):
# analyzeHeadless <project_dir> <project_name> -import <binary> \
#   -postScript ExportProgramFacts.py <output.json>

from ghidra.program.model.data import StringDataInstance
from ghidra.util.task import TaskMonitor
from java.io import FileWriter
import json
import sys


def addr(x):
    return str(x) if x is not None else None


def safe_name(obj):
    try:
        return obj.getName()
    except:
        return None


def function_record(fm, fn):
    body = fn.getBody()
    refs_in = 0
    refs_out = 0

    it = body.getAddresses(True)
    while it.hasNext():
        a = it.next()
        refs_in += len(getReferencesTo(a))
        refs_out += len(getReferencesFrom(a))

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
            out.append({
                "address": addr(d.getAddress()),
                "length": d.getLength(),
                "value": text,
                "xrefs": len(getReferencesTo(d.getAddress())),
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
        out.append({
            "name": s.getName(),
            "address": addr(s.getAddress()),
            "type": str(s.getSymbolType()),
            "source": str(s.getSource()),
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
        functions.append(function_record(fm, it.next()))

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
        "schema_version": 1,
        "program": {
            "name": currentProgram.getName(),
            "language": str(currentProgram.getLanguageID()),
            "compiler": str(currentProgram.getCompilerSpec().getCompilerSpecID()),
            "image_base": addr(currentProgram.getImageBase()),
            "executable_format": currentProgram.getExecutableFormat(),
        },
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
