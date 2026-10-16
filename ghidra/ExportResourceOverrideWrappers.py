# Ghidra/PyGhidra: find wrapper-like functions that call a base constructor
# and then overwrite a small set of function pointers with resource-getter-like targets.
# Usage: -postScript ExportResourceOverrideWrappers.py <output.json> <xp|win7>
import json,re
from ghidra.app.decompiler import DecompInterface

MAX_FUNC_SIZE=0x600
MAX_DECOMP=24000
CALL_RE=re.compile(r"(FUN_[0-9a-fA-F]+)\s*\(")
ASSIGN_RE=re.compile(r"\*\((?:code|undefined[1248])\s*\*\*\)\(param_\d+\s*\+\s*(0x[0-9a-fA-F]+|\d+)\)\s*=\s*(FUN_[0-9a-fA-F]+)")

space=currentProgram.getAddressFactory().getDefaultAddressSpace()
listing=currentProgram.getListing()
mem=currentProgram.getMemory()

def fnhex(name):
    try:
        a=space.getAddress(int(name.split("_")[-1],16))
        f=getFunctionAt(a)
        return f if f else getFunctionContaining(a)
    except:
        return None

def target_shape(f):
    if not f: return None
    ins=0; calls=0; data=[]
    it=listing.getInstructions(f.getBody(),True)
    while it.hasNext():
        x=it.next(); ins+=1
        for r in x.getReferencesFrom():
            try:
                if r.getReferenceType().isCall(): calls+=1
                elif r.getReferenceType().isData():
                    a=r.getToAddress(); b=mem.getBlock(a)
                    sec=b.getName() if b else None
                    if sec not in (None,".text",".pdata") and len(data)<12:
                        data.append({"to":str(a),"section":sec})
            except: pass
    return {"size":int(f.getBody().getNumAddresses()),"instructions":ins,"calls":calls,
            "noncode_data_refs":data}

args=getScriptArgs()
if len(args)!=2: raise ValueError("expected output.json xp|win7")
out,platform=args
dec=DecompInterface(); dec.openProgram(currentProgram)
rows=[]
it=currentProgram.getFunctionManager().getFunctions(True)
while it.hasNext():
    f=it.next()
    if f.isExternal() or int(f.getBody().getNumAddresses())>MAX_FUNC_SIZE: continue
    d=dec.decompileFunction(f,8,monitor)
    if not d.decompileCompleted() or not d.getDecompiledFunction(): continue
    c=str(d.getDecompiledFunction().getC())
    calls=CALL_RE.findall(c)
    assigns=ASSIGN_RE.findall(c)
    if not calls or not (1 <= len(assigns) <= 4): continue
    enriched=[]
    getterish=0
    for off,t in assigns:
        tf=fnhex(t); sh=target_shape(tf)
        if sh and sh["size"]<=0x180 and sh["calls"]<=2 and sh["noncode_data_refs"]:
            getterish+=1
        enriched.append({"offset":int(off,0),"target":t,"target_shape":sh})
    if getterish==0: continue
    base_calls=[]
    seen=set()
    for name in calls:
        if name in seen: continue
        seen.add(name)
        bf=fnhex(name)
        base_calls.append({"target":name,"shape":target_shape(bf)})
    rows.append({"entry":str(f.getEntryPoint()),"size":int(f.getBody().getNumAddresses()),
                 "base_calls":base_calls[:16],"assignments":enriched,
                 "getterish_count":getterish,
                 "score":round(min(1.0,0.45+0.15*getterish+0.05*len(assigns)),3),
                 "decompilation":c[:MAX_DECOMP]})
rows.sort(key=lambda x:(-x["score"],-x["getterish_count"],x["entry"]))
with open(out,"w") as h:
    json.dump({"schema_version":1,"platform":platform,
               "caveat":"Static wrapper heuristic modeled after SupraGSX call-base-then-override pattern; not proof of GP106 identity.",
               "candidates":rows[:160]},h,indent=2)
dec.dispose()
print("resource override wrapper candidates: %d"%len(rows))
