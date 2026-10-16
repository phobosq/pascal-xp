# Ghidra/PyGhidra: trace callers of known FECS helpers and detect compact callback override wrappers.
# Usage: -postScript ExportFecsHelperCallers.py <output.json> <xp|win7>
import json,re
from ghidra.app.decompiler import DecompInterface

HELPERS={
 "xp":["000715d0","000716c0"],
 "win7":["00199394","00197ae8"],
}
ASSIGN_RE=re.compile(r"\*\((?:code|undefined[1248])\s*\*\*\)\((param_\d+)\s*\+\s*(0x[0-9a-fA-F]+|\d+)\)\s*=\s*(FUN_[0-9a-fA-F]+)")
MAX_DECOMP=32000

space=currentProgram.getAddressFactory().getDefaultAddressSpace()
mem=currentProgram.getMemory()

def A(s): return space.getAddress(int(s,16))
def fn(a):
    f=getFunctionAt(a)
    return f if f else getFunctionContaining(a)
def sec(a):
    b=mem.getBlock(a)
    return b.getName() if b else None

args=getScriptArgs()
if len(args)!=2 or args[1] not in HELPERS: raise ValueError("expected output.json xp|win7")
out,platform=args
dec=DecompInterface();dec.openProgram(currentProgram)
callers={}
for hs in HELPERS[platform]:
    ha=A(hs)
    for r in getReferencesTo(ha):
        src=r.getFromAddress()
        if sec(src)==".pdata": continue
        f=fn(src)
        if not f or f.isExternal(): continue
        k=str(f.getEntryPoint())
        callers.setdefault(k,{"fn":f,"helpers":[]})
        if hs not in callers[k]["helpers"]: callers[k]["helpers"].append(hs)

rows=[]
for k,obj in sorted(callers.items()):
    f=obj["fn"]
    d=dec.decompileFunction(f,30,monitor)
    code=None; assigns=[]
    if d.decompileCompleted() and d.getDecompiledFunction():
        code=str(d.getDecompiledFunction().getC())
        for base,off,target in ASSIGN_RE.findall(code):
            assigns.append({"base":base,"offset":int(off,0),"target":target})
    groups={}
    for a in assigns:
        groups.setdefault(a["base"],[]).append(a)
    compact=[]
    for base,arr in groups.items():
        offs=sorted(set(x["offset"] for x in arr))
        consecutive=False
        if 3<=len(offs)<=6:
            consecutive=all((b-a)==8 for a,b in zip(offs,offs[1:]))
        compact.append({"base":base,"offsets":offs,"assignments":arr,
                        "consecutive_qword_cluster":consecutive})
    rows.append({"entry":k,"size":int(f.getBody().getNumAddresses()),
                 "helper_calls":obj["helpers"],"callback_groups":compact,
                 "decompilation":code[:MAX_DECOMP] if code else None})
dec.dispose()
with open(out,"w") as h:
    json.dump({"schema_version":1,"platform":platform,"callers":rows},h,indent=2)
print("FECS helper callers: %d"%len(rows))
