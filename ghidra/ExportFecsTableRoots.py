# Ghidra/PyGhidra: trace real FECS callback-table roots and second-order owners.
# Usage: -postScript ExportFecsTableRoots.py <output.json> <xp|win7>
import json
from ghidra.app.decompiler import DecompInterface

TABLES = {
    "xp": {
        "primary": ["005eee60", "005eeef0", "005eef80"],
        "alternate": ["005f5510", "005f55a0"],
    },
    "win7": {
        "primary": ["00ce7500", "00ce7590", "00ce7620"],
        "alternate": ["00ce6ae0", "00ce6b70"],
    },
}
MAX_REFS = 128
MAX_OWNER_DECOMP = 30000
NEAR = 0x200

space = currentProgram.getAddressFactory().getDefaultAddressSpace()
mem = currentProgram.getMemory()
listing = currentProgram.getListing()

def A(s):
    return space.getAddress(int(s,16) if isinstance(s,str) else int(s))

def section(a):
    b=mem.getBlock(a)
    return b.getName() if b else None

def fn_containing(a):
    f=getFunctionAt(a)
    return f if f else getFunctionContaining(a)

def refs_to(a):
    out=[]
    for r in getReferencesTo(a):
        src=r.getFromAddress()
        sec=section(src)
        if sec==".pdata":
            continue
        f=fn_containing(src)
        out.append({
            "from":str(src),"type":str(r.getReferenceType()),"section":sec,
            "owner":str(f.getEntryPoint()) if f else None
        })
        if len(out)>=MAX_REFS: break
    return out

def ptr64(a):
    try:
        v=int(mem.getLong(a)) & 0xffffffffffffffff
        if v==0:return None
        d=A(v)
        b=mem.getBlock(d)
        if b is None:return None
        f=fn_containing(d)
        return {"address":str(a),"value":"0x%x"%v,"target":str(d),
                "target_section":section(d),"target_function":str(f.getEntryPoint()) if f else None}
    except:
        return None

def owner_record(entry, dec):
    f=fn_containing(A(entry))
    if f is None:return None
    calls=[]
    it=listing.getInstructions(f.getBody(),True)
    while it.hasNext() and len(calls)<128:
        ins=it.next()
        for r in ins.getReferencesFrom():
            if r.getReferenceType().isCall():
                cal=fn_containing(r.getToAddress())
                calls.append({"site":str(ins.getAddress()),"to":str(r.getToAddress()),
                              "callee":str(cal.getEntryPoint()) if cal else None})
    dr=dec.decompileFunction(f,60,monitor)
    code=None
    if dr.decompileCompleted() and dr.getDecompiledFunction():
        code=str(dr.getDecompiledFunction().getC())[:MAX_OWNER_DECOMP]
    return {"entry":str(f.getEntryPoint()),"name":f.getName(),"size":int(f.getBody().getNumAddresses()),
            "references":refs_to(f.getEntryPoint()),"calls":calls,"decompilation":code}

def around(root):
    base=int(root.getOffset())
    out=[]
    seen=set()
    for off in range(base-NEAR,base+NEAR+1,8):
        a=A(off)
        if section(a)!=section(root): continue
        p=ptr64(a)
        rr=refs_to(a)
        if p or rr:
            item={"relative":off-base,"address":str(a),"pointer":p,"references":rr}
            key=(item["address"], json.dumps(rr,sort_keys=True), json.dumps(p,sort_keys=True) if p else "")
            if key not in seen:
                out.append(item);seen.add(key)
    return out

args=getScriptArgs()
if len(args)!=2 or args[1] not in TABLES:
    raise ValueError("expected output.json xp|win7")
out,platform=args
dec=DecompInterface();dec.openProgram(currentProgram)
roots=[]
owners={}
for role,sites in TABLES[platform].items():
    for s in sites:
        r=A(s)
        direct=refs_to(r)
        win=around(r)
        roots.append({"role":role,"root":str(r),"section":section(r),"references":direct,"neighborhood":win})
        for ref in direct:
            if ref.get("owner"): owners[ref["owner"]]=1
        for item in win:
            for ref in item["references"]:
                if ref.get("owner"): owners[ref["owner"]]=1
owner_details=[x for x in (owner_record(e,dec) for e in sorted(owners)) if x]
with open(out,"w") as f:
    json.dump({"schema_version":1,"platform":platform,
               "caveat":"Static xrefs and table proximity do not prove GP106 runtime selection.",
               "roots":roots,"owners":owner_details},f,indent=2)
dec.dispose()
print("FECS table roots: %d owners: %d"%(len(roots),len(owner_details)))
