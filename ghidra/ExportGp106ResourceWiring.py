# Ghidra/PyGhidra: identify GP106 FECS/GPCCS/GR constructors and resource getter wiring.
# Usage: -postScript ExportGp106ResourceWiring.py <output.json> <xp|win7>
# Semantic/static analysis only. x86 SupraGSX offsets are NOT reused here.
import json
from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.symbol import RefType

TERMS = ["GP106","FECS","GPCCS","RMFECSSETUCODE","UCODE","FIRMWARE"]
MAX_SEEDS=160
MAX_NEIGHBORS=320
MAX_DECOMP=50000

listing=currentProgram.getListing()
mem=currentProgram.getMemory()

def sec(a):
    b=mem.getBlock(a)
    return b.getName() if b else None

def fn_at(a):
    f=getFunctionAt(a)
    return f if f else getFunctionContaining(a)

def add_fn(dst, fn, why):
    if fn is None or fn.isExternal(): return
    k=str(fn.getEntryPoint())
    x=dst.setdefault(k,{"fn":fn,"reasons":[]})
    if why not in x["reasons"]: x["reasons"].append(why)

def seed_strings(dst):
    it=listing.getDefinedData(True)
    while it.hasNext() and len(dst)<MAX_SEEDS:
        d=it.next()
        try:
            if not d.hasStringValue(): continue
            s=str(d.getValue())
            u=s.upper()
            hits=[t for t in TERMS if t in u]
            if not hits: continue
            for r in getReferencesTo(d.getAddress()):
                add_fn(dst,fn_at(r.getFromAddress()),"string:"+",".join(hits)+":"+s[:120])
        except: pass

def expand(dst):
    initial=list(dst.items())
    for k,obj in initial:
        fn=obj["fn"]
        for r in getReferencesTo(fn.getEntryPoint()):
            try: add_fn(dst,fn_at(r.getFromAddress()),"caller-of:"+k)
            except: pass
        it=listing.getInstructions(fn.getBody(),True)
        while it.hasNext():
            ins=it.next()
            for r in ins.getReferencesFrom():
                try:
                    if r.getReferenceType().isCall():
                        add_fn(dst,fn_at(r.getToAddress()),"callee-of:"+k)
                except: pass
            if len(dst)>=MAX_NEIGHBORS: return

def ptr_targets(fn):
    out=[]
    it=listing.getInstructions(fn.getBody(),True)
    while it.hasNext():
        ins=it.next()
        for r in ins.getReferencesFrom():
            try:
                rt=r.getReferenceType()
                if not (rt.isData() or rt.isCall()): continue
                to=r.getToAddress()
                tf=fn_at(to)
                out.append({"site":str(ins.getAddress()),"text":str(ins),
                            "type":str(rt),"to":str(to),"target_function":str(tf.getEntryPoint()) if tf else None,
                            "target_section":sec(to)})
            except: pass
    return out[:300]

def getter_score(fn):
    # Heuristic: short function with data refs and few/no calls often wraps a resource descriptor.
    insns=0; calls=0; datarefs=0; targets=[]
    it=listing.getInstructions(fn.getBody(),True)
    while it.hasNext():
        ins=it.next(); insns+=1
        for r in ins.getReferencesFrom():
            try:
                if r.getReferenceType().isCall(): calls+=1
                elif r.getReferenceType().isData():
                    datarefs+=1
                    if len(targets)<16:
                        targets.append({"from":str(ins.getAddress()),"to":str(r.getToAddress()),"section":sec(r.getToAddress())})
            except: pass
    score=0
    if insns<=40: score+=2
    if calls<=1: score+=2
    if datarefs>0: score+=2
    if any(t.get("section") not in (None,".text",".pdata") for t in targets): score+=2
    return {"score":score,"instructions":insns,"calls":calls,"data_refs":datarefs,"data_targets":targets}

def analyze(entry,obj,dec):
    fn=obj["fn"]
    dr=dec.decompileFunction(fn,60,monitor)
    code=None
    if dr.decompileCompleted() and dr.getDecompiledFunction():
        code=str(dr.getDecompiledFunction().getC())[:MAX_DECOMP]
    refs=ptr_targets(fn)
    getters=[]
    seen=set()
    for r in refs:
        tf=r.get("target_function")
        if not tf or tf in seen or tf==entry: continue
        seen.add(tf)
        gfn=fn_at(currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(int(tf,16)))
        if gfn:
            gs=getter_score(gfn)
            if gs["score"]>=4:
                getters.append({"entry":tf,"via":r["site"],"heuristic":gs})
    return {"entry":entry,"name":fn.getName(),"size":int(fn.getBody().getNumAddresses()),
            "reasons":obj["reasons"],"references":refs,"getter_candidates":getters,
            "decompilation":code}

args=getScriptArgs()
if len(args)!=2: raise ValueError("expected output.json xp|win7")
out,platform=args
sel={}
seed_strings(sel); expand(sel)
dec=DecompInterface();dec.openProgram(currentProgram)
items=[]
for entry,obj in sorted(sel.items()):
    reasons=" ".join(obj["reasons"]).upper()
    # Favor direct GP106 and FECS/GPCCS seeds plus close neighbors.
    if ("GP106" in reasons or "FECS" in reasons or "GPCCS" in reasons or
        any(x.startswith("caller-of:") or x.startswith("callee-of:") for x in obj["reasons"])):
        items.append(analyze(entry,obj,dec))
with open(out,"w") as f:
    json.dump({"schema_version":1,"platform":platform,
               "caveat":"Static semantic candidates only; no x86 object offsets are assumed and no runtime GP106 selection is proven.",
               "functions":items},f,indent=2)
dec.dispose()
print("GP106 resource wiring candidates: %d"%len(items))
