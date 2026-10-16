# Ghidra/PyGhidra: find constructor-like functions that wire clusters of function pointers.
# Usage: -postScript ExportGp106ConstructorPatterns.py <output.json> <xp|win7>
# No x86 SupraGSX offsets are assumed.
import json, re
from ghidra.app.decompiler import DecompInterface

MAX_FUNCS=5000
MAX_DECOMP=30000
MIN_WRITES=3
MAX_SPAN=0x500

ASSIGN=re.compile(r"\*\((?:code|undefined[1248])\s*\*\*\)\(param_\d+\s*\+\s*(0x[0-9a-fA-F]+|\d+)\)\s*=\s*(FUN_[0-9a-fA-F]+)")

listing=currentProgram.getListing()
space=currentProgram.getAddressFactory().getDefaultAddressSpace()
mem=currentProgram.getMemory()

def fn_at_hex(s):
    try:
        a=space.getAddress(int(s,16))
        f=getFunctionAt(a)
        return f if f else getFunctionContaining(a)
    except:
        return None

def fn_shape(fn):
    ins=0; calls=0; data=0
    it=listing.getInstructions(fn.getBody(),True)
    while it.hasNext():
        x=it.next(); ins+=1
        for r in x.getReferencesFrom():
            try:
                if r.getReferenceType().isCall(): calls+=1
                elif r.getReferenceType().isData(): data+=1
            except: pass
    return {"size":int(fn.getBody().getNumAddresses()),"instructions":ins,"calls":calls,"data_refs":data}

args=getScriptArgs()
if len(args)!=2: raise ValueError("expected output.json xp|win7")
out,platform=args
dec=DecompInterface();dec.openProgram(currentProgram)
rows=[]
fm=currentProgram.getFunctionManager()
it=fm.getFunctions(True)
count=0
while it.hasNext() and count<MAX_FUNCS:
    fn=it.next();count+=1
    if fn.isExternal(): continue
    dr=dec.decompileFunction(fn,20,monitor)
    if not dr.decompileCompleted() or not dr.getDecompiledFunction(): continue
    code=str(dr.getDecompiledFunction().getC())
    matches=ASSIGN.findall(code)
    if len(matches)<MIN_WRITES: continue
    assigns=[]
    for off,target in matches:
        val=int(off,0)
        tf=fn_at_hex(target.split("_")[-1])
        assigns.append({"offset":val,"target":target,"target_shape":fn_shape(tf) if tf else None})
    offs=sorted(set(x["offset"] for x in assigns))
    if len(offs)<MIN_WRITES or offs[-1]-offs[0]>MAX_SPAN: continue
    # SupraGSX-like constructors tend to wire several nearby getters and often one farther GR pointer.
    short_getters=sum(1 for x in assigns if x["target_shape"] and x["target_shape"]["size"]<=256 and x["target_shape"]["calls"]<=2)
    score=min(1.0, 0.12*len(offs)+0.08*short_getters)
    rows.append({"entry":str(fn.getEntryPoint()),"name":fn.getName(),"function_size":int(fn.getBody().getNumAddresses()),
                 "offsets":offs,"assignments":assigns,"short_getters":short_getters,
                 "pattern_score":round(score,3),"decompilation":code[:MAX_DECOMP]})
rows.sort(key=lambda x:(-x["pattern_score"],-len(x["offsets"]),x["entry"]))
with open(out,"w") as f:
    json.dump({"schema_version":1,"platform":platform,
               "caveat":"Structural constructor candidates only; no GP106 identity or ABI equivalence is proven.",
               "candidates":rows[:200]},f,indent=2)
dec.dispose()
print("constructor pattern candidates: %d"%len(rows))
