# Ghidra headless: targeted FECS initialization trace for XP/Win7 368.81.
# Usage: -postScript ExportFecsTrace.py <output.json> <xp|win7>
from java.io import FileWriter
from ghidra.app.decompiler import DecompInterface
import json

SEEDS = {
    "xp": ["002828f0", "00260170"],
    "win7": ["00314c60", "0037d8c0"]
}
MAX_CALLS = 128
MAX_REFERENCES = 128
MAX_DECOMPILATION = 45000

def function_at_hex(s):
    a = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(int(s, 16))
    return getFunctionContaining(a)

def describe(fn, decompiler):
    entry = fn.getEntryPoint()
    listing = currentProgram.getListing()
    calls = []
    iter_ins = listing.getInstructions(fn.getBody(), True)
    while iter_ins.hasNext():
        insn = iter_ins.next()
        for ref in insn.getReferencesFrom():
            if ref.getReferenceType().isCall() and len(calls) < MAX_CALLS:
                target = getFunctionContaining(ref.getToAddress())
                calls.append({"site": str(insn.getAddress()), "target": str(ref.getToAddress()),
                              "target_entry": str(target.getEntryPoint()) if target else None})
    incoming = []
    for ref in getReferencesTo(entry):
        if len(incoming) >= MAX_REFERENCES:
            break
        owner = getFunctionContaining(ref.getFromAddress())
        incoming.append({"site": str(ref.getFromAddress()),
                         "type": str(ref.getReferenceType()),
                         "owner": str(owner.getEntryPoint()) if owner else None})
    result = decompiler.decompileFunction(fn, 90, monitor)
    dec = str(result.getDecompiledFunction().getC()) if result.decompileCompleted() and result.getDecompiledFunction() else None
    return {"entry": str(entry), "name": fn.getName(), "size": fn.getBody().getNumAddresses(),
            "calls": calls, "incoming": incoming,
            "decompilation": dec[:MAX_DECOMPILATION] if dec else None,
            "decompilation_truncated": bool(dec and len(dec) > MAX_DECOMPILATION)}

args = getScriptArgs()
if len(args) != 2 or args[1] not in SEEDS:
    raise ValueError("Expected <output.json> <xp|win7>")
out_file, platform = args
dec = DecompInterface()
dec.openProgram(currentProgram)
functions = []
missing = []
for seed in SEEDS[platform]:
    fn = function_at_hex(seed)
    if fn is None:
        missing.append(seed)
    elif str(fn.getEntryPoint()) not in [x["entry"] for x in functions]:
        functions.append(describe(fn, dec))
with open(out_file, "w") as f:
    json.dump({"platform": platform, "program": currentProgram.getName(),
               "seeds": SEEDS[platform], "missing": missing,
               "functions": functions}, f, indent=2)
dec.dispose()
print("FECS trace: %d functions, %d missing" % (len(functions), len(missing)))
