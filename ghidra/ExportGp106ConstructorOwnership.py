# Ghidra/PyGhidra: enrich constructor-pattern candidates with incoming ownership/xrefs.
# Usage: -postScript ExportGp106ConstructorOwnership.py <patterns.json> <output.json> <platform>
import json

MAX_CANDIDATES=200
MAX_REFS=80
MAX_SECOND=80

space=currentProgram.getAddressFactory().getDefaultAddressSpace()
mem=currentProgram.getMemory()

def A(s):
    return space.getAddress(int(str(s),16))

def fn_containing(a):
    f=getFunctionAt(a)
    return f if f else getFunctionContaining(a)

def sec(a):
    b=mem.getBlock(a)
    return b.getName() if b else None

def incoming(addr):
    rows=[]
    for r in getReferencesTo(addr):
        src=r.getFromAddress()
        if sec(src)==".pdata": continue
        f=fn_containing(src)
        rows.append({"from":str(src),"type":str(r.getReferenceType()),"section":sec(src),
                     "owner":str(f.getEntryPoint()) if f else None})
        if len(rows)>=MAX_REFS: break
    return rows

def second_order(owners):
    out=[]
    seen=set()
    for o in owners:
        if not o or o in seen: continue
        seen.add(o)
        try: fn=fn_containing(A(o))
        except: fn=None
        if fn is None: continue
        for r in getReferencesTo(fn.getEntryPoint()):
            src=r.getFromAddress()
            if sec(src)==".pdata": continue
            f=fn_containing(src)
            rec={"target_owner":o,"from":str(src),"type":str(r.getReferenceType()),"section":sec(src),
                 "owner":str(f.getEntryPoint()) if f else None}
            out.append(rec)
            if len(out)>=MAX_SECOND: return out
    return out

args=getScriptArgs()
if len(args)!=3: raise ValueError("expected patterns.json output.json platform")
patterns_path,out,platform=args
data=json.load(open(patterns_path))
rows=[]
for c in data.get("candidates",[])[:MAX_CANDIDATES]:
    entry=c.get("entry")
    try: inc=incoming(A(entry))
    except: inc=[]
    direct_owners=sorted(set(x["owner"] for x in inc if x.get("owner")))
    getter_refs=[]
    for a in c.get("assignments",[]):
        target=a.get("target","")
        if not target.startswith("FUN_"): continue
        try: ga=A(target.split("_")[-1])
        except: continue
        gi=incoming(ga)
        getter_refs.append({"target":target,"incoming":gi,
                            "owners":sorted(set(x["owner"] for x in gi if x.get("owner")))})
    rows.append({"entry":entry,"offsets":c.get("offsets",[]),"pattern_score":c.get("pattern_score"),
                 "function_size":c.get("function_size"),"assignments":c.get("assignments",[]),
                 "incoming":inc,"direct_owners":direct_owners,
                 "second_order":second_order(direct_owners),"getter_incoming":getter_refs})
with open(out,"w") as f:
    json.dump({"schema_version":1,"platform":platform,
               "caveat":"Static xrefs only; ownership and runtime GP106 selection are not proven.",
               "candidates":rows},f,indent=2)
print("constructor ownership candidates: %d"%len(rows))
