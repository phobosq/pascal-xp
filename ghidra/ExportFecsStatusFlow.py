# Ghidra/PyGhidra: trace FECS status propagation without altering the driver.
# Usage: -postScript ExportFecsStatusFlow.py <output.json> <xp|win7>
import json
from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.lang import OperandType
from ghidra.program.model.scalar import Scalar

SEEDS = {
    "xp": {"primary": "00282ab0", "alternate": "00260720", "status": "0026bd10"},
    "win7": {"primary": "00314b38", "alternate": "0037d774", "status": "002fd6f8"},
}
MAX_CALLERS = 48
MAX_DECOMP = 65000
MAX_CALLS = 200

def addr(s):
    return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(int(s, 16))

def find_fn(s):
    return getFunctionContaining(addr(s))

def context(a, before=5, after=7):
    listing = currentProgram.getListing()
    center = listing.getInstructionContaining(a)
    if center is None:
        return []
    preceding = []
    cursor = center
    for _ in range(before):
        cursor = listing.getInstructionBefore(cursor.getAddress())
        if cursor is None:
            break
        preceding.append(cursor)
    preceding.reverse()
    result = preceding + [center]
    cursor = center
    for _ in range(after):
        cursor = listing.getInstructionAfter(cursor.getAddress())
        if cursor is None:
            break
        result.append(cursor)
    return [{"address": str(i.getAddress()), "text": str(i)} for i in result]

def immediate_values(insn):
    # Memory displacements must NOT be treated as architecture/status immediates.
    values = []
    for n in range(insn.getNumOperands()):
        kind = insn.getOperandType(n)
        rep = insn.getDefaultOperandRepresentation(n)
        if not OperandType.isScalar(kind) or (rep is not None and "[" in rep):
            continue
        for obj in insn.getOpObjects(n):
            if isinstance(obj, Scalar):
                values.append({"operand": n, "value": int(obj.getUnsignedValue())})
    return values

def describe(fn, decompiler):
    listing = currentProgram.getListing()
    calls, indirect, returns, tests = [], [], [], []
    it = listing.getInstructions(fn.getBody(), True)
    while it.hasNext():
        insn = it.next()
        mnemonic = insn.getMnemonicString().upper()
        if mnemonic in ("CMP", "TEST", "SUB"):
            values = immediate_values(insn)
            if values and len(tests) < 120:
                tests.append({"site": str(insn.getAddress()), "instruction": str(insn),
                              "immediates": values})
        if mnemonic.startswith("RET") and len(returns) < 60:
            returns.append({"site": str(insn.getAddress()),
                            "context": context(insn.getAddress(), 5, 0)})
        if insn.getFlowType().isCall():
            direct = False
            for ref in insn.getReferencesFrom():
                if ref.getReferenceType().isCall():
                    direct = True
                    if len(calls) < MAX_CALLS:
                        callee = getFunctionContaining(ref.getToAddress())
                        calls.append({"site": str(insn.getAddress()), "target": str(ref.getToAddress()),
                                      "callee_entry": str(callee.getEntryPoint()) if callee else None})
            if not direct and len(indirect) < MAX_CALLS:
                indirect.append({"site": str(insn.getAddress()), "instruction": str(insn),
                                 "context": context(insn.getAddress(), 2, 2)})
    dec = decompiler.decompileFunction(fn, 90, monitor)
    c = str(dec.getDecompiledFunction().getC()) if dec.decompileCompleted() and dec.getDecompiledFunction() else None
    return {"entry": str(fn.getEntryPoint()), "name": fn.getName(),
            "size": int(fn.getBody().getNumAddresses()), "calls": calls,
            "indirect_calls": indirect, "return_sites": returns, "tests": tests,
            "decompilation": c[:MAX_DECOMP] if c else None,
            "decompilation_truncated": bool(c and len(c) > MAX_DECOMP)}

def caller_sites(fn):
    out, seen = [], set()
    for ref in getReferencesTo(fn.getEntryPoint()):
        if not ref.getReferenceType().isCall():
            continue
        caller = getFunctionContaining(ref.getFromAddress())
        if caller is None or caller.isExternal():
            continue
        key = (str(ref.getFromAddress()), str(caller.getEntryPoint()))
        if key in seen:
            continue
        seen.add(key)
        out.append({"site": key[0], "caller_entry": key[1],
                    "context": context(ref.getFromAddress())})
        if len(out) >= MAX_CALLERS:
            break
    return out

args = getScriptArgs()
if len(args) != 2 or args[1] not in SEEDS:
    raise ValueError("expected <output.json> <xp|win7>")
output, platform = args
dec = DecompInterface()
dec.openProgram(currentProgram)
functions, missing = {}, []
for role, seed in SEEDS[platform].items():
    fn = find_fn(seed)
    if fn is None:
        missing.append({"role": role, "seed": seed})
        continue
    functions[role] = describe(fn, dec)
    functions[role]["seed"] = seed
    functions[role]["callers"] = caller_sites(fn)
result = {"schema_version": 1, "platform": platform,
          "source_run": 25, "seeds": SEEDS[platform],
          "missing": missing, "functions": functions}
with open(output, "w") as f:
    json.dump(result, f, indent=2)
dec.dispose()
print("FECS status flow: %s, %d functions, %d missing" %
      (platform, len(functions), len(missing)))
