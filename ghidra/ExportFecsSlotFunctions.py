# Targeted semantic comparison of FECS table callback slots discovered in run #23.
# Usage: -postScript ExportFecsSlotFunctions.py <output.json> <xp|win7>
import json
from ghidra.app.decompiler import DecompInterface

TARGETS = {
    "xp": {
        "primary": ["00282ab0", "00282460", "002824b0"],
        "alternate": ["00260720", "002606f0"],
        "table_consumers": ["000eecd0", "000eed10", "000eed50", "000eeec0", "000eef00", "000eef40"]
    },
    "win7": {
        "primary": ["00314b38", "0031b6c4", "0031b680"],
        "alternate": ["0037d774", "0037dd34"],
        "table_consumers": ["0093c7ac", "0093d360", "009432cc", "00943dd0"]
    }
}
def find(s):
    a=currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(int(s,16))
    return getFunctionContaining(a)
def analyze(seed,role,decompiler):
    fn=find(seed)
    if fn is None:return {"seed":seed,"role":role,"missing":True}
    refs=[]
    for r in getReferencesTo(fn.getEntryPoint()):
        if len(refs)>=100:break
        owner=getFunctionContaining(r.getFromAddress())
        refs.append({"source":str(r.getFromAddress()),"type":str(r.getReferenceType()),
                     "owner":str(owner.getEntryPoint()) if owner else None})
    calls=[]
    it=currentProgram.getListing().getInstructions(fn.getBody(),True)
    while it.hasNext():
        insn=it.next()
        for r in insn.getReferencesFrom():
            if r.getReferenceType().isCall() and len(calls)<150:
                callee=getFunctionContaining(r.getToAddress())
                calls.append({"site":str(insn.getAddress()),"target":str(r.getToAddress()),
                              "callee":str(callee.getEntryPoint()) if callee else None})
    d=decompiler.decompileFunction(fn,90,monitor)
    code=str(d.getDecompiledFunction().getC()) if d.decompileCompleted() and d.getDecompiledFunction() else None
    return {"seed":seed,"role":role,"entry":str(fn.getEntryPoint()),"name":fn.getName(),
            "references":refs,"calls":calls,"decompilation":code[:60000] if code else None,
            "truncated":bool(code and len(code)>60000)}
args=getScriptArgs()
if len(args)!=2 or args[1] not in TARGETS:raise ValueError("expected output.json xp|win7")
out,platform=args
dec=DecompInterface()
dec.openProgram(currentProgram)
results=[]
for role,seeds in TARGETS[platform].items():
    for seed in seeds:results.append(analyze(seed,role,dec))
with open(out,"w") as f:json.dump({"platform":platform,"provenance":"Driver analysis #23 FECS callback slots","functions":results},f,indent=2)
dec.dispose()
print("FECS slot functions: "+str(len(results)))
