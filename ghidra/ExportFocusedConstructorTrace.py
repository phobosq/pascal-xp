# Ghidra/PyGhidra: deep trace selected constructor candidates and their getter targets.
# Usage: -postScript ExportFocusedConstructorTrace.py <output.json> <platform>
import json
from ghidra.app.decompiler import DecompInterface

TARGETS={
 "xp":["000b6e40","0018f0a0","004e25c0","003cf290"],
 "win7":["003242a4","0025c97c","005737a4","0046d474","004fab14","004fb48c","004fa748","004fba94","005a13c4","005a1260"],
}
MAX_REFS=128
MAX_DECOMP=40000

space=currentProgram.getAddressFactory().getDefaultAddressSpace()
listing=currentProgram.getListing()
mem=currentProgram.getMemory()

def A(s): return space.getAddress(int(s,16))
def sec(a):
    b=mem.getBlock(a)
    return b.getName() if b else None
def fn(a):
    f=getFunctionAt(a)
    return f if f else getFunctionContaining(a)
def refs_to(a):
    out=[]
    for r in getReferencesTo(a):
        src=r.getFromAddress()
        if sec(src)==".pdata": continue
        f=fn(src)
        out.append({"from":str(src),"type":str(r.getReferenceType()),"section":sec(src),
                    "owner":str(f.getEntryPoint()) if f else None})
        if len(out)>=MAX_REFS: break
    return out
def refs_from_func(f):
    out=[]
    it=listing.getInstructions(f.getBody(),True)
    while it.hasNext():
        ins=it.next()
        for r in ins.getReferencesFrom():
            try:
                t=r.getToAddress()
                tf=fn(t)
                out.append({"site":str(ins.getAddress()),"text":str(ins),"type":str(r.getReferenceType()),
                            "to":str(t),"section":sec(t),"target_function":str(tf.getEntryPoint()) if tf else None})
            except: pass
    return out[:512]
def decomp(f,dec):
    d=dec.decompileFunction(f,45,monitor)
    if d.decompileCompleted() and d.getDecompiledFunction():
        return str(d.getDecompiledFunction().getC())[:MAX_DECOMP]
    return None

args=getScriptArgs()
if len(args)!=2 or args[1] not in TARGETS: raise ValueError("expected output.json xp|win7")
out,platform=args
dec=DecompInterface(); dec.openProgram(currentProgram)
rows=[]
for e in TARGETS[platform]:
    f=fn(A(e))
    if not f: continue
    incoming=refs_to(f.getEntryPoint())
    outgoing=refs_from_func(f)
    callees=[]
    for x in outgoing:
        tf=x.get("target_function")
        if tf and tf not in callees: callees.append(tf)
    callee_rows=[]
    for ce in callees[:64]:
        cf=fn(A(ce))
        if not cf: continue
        callee_rows.append({"entry":ce,"incoming":refs_to(cf.getEntryPoint()),
                            "outgoing":refs_from_func(cf)[:96],
                            "decompilation":decomp(cf,dec)})
    owners=sorted(set(x["owner"] for x in incoming if x.get("owner")))
    owner_rows=[]
    for oe in owners[:64]:
        of=fn(A(oe))
        if not of: continue
        owner_rows.append({"entry":oe,"incoming":refs_to(of.getEntryPoint()),
                           "outgoing":refs_from_func(of)[:160],
                           "decompilation":decomp(of,dec)})
    rows.append({"entry":e,"incoming":incoming,"outgoing":outgoing,
                 "owners":owner_rows,"callees":callee_rows,
                 "decompilation":decomp(f,dec)})
dec.dispose()
with open(out,"w") as f:
    json.dump({"schema_version":1,"platform":platform,"targets":rows},f,indent=2)
print("focused constructor traces: %d"%len(rows))
