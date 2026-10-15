# Ghidra headless: inspect FECS callback-table owners and the shared callee.
# -postScript ExportFecsTables.py <out.json> <xp|win7>
import json
from ghidra.app.decompiler import DecompInterface
SEEDS = {
 "xp": {"functions": ["002828f0","00260170"],"shared":"000715d0"},
 "win7": {"functions": ["00314c60","0037d8c0"],"shared":"00199394"}
}
def lookup(s):
 a=currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(int(s,16))
 return getFunctionContaining(a)
def decompile(fn,dec):
 r=dec.decompileFunction(fn,90,monitor)
 d=r.getDecompiledFunction() if r.decompileCompleted() else None
 return str(d.getC())[:30000] if d else None
def table_refs(fn):
 mem=currentProgram.getMemory()
 sp=currentProgram.getAddressFactory().getDefaultAddressSpace()
 out=[]
 for ref in getReferencesTo(fn.getEntryPoint()):
  if str(ref.getReferenceType())!="DATA":continue
  a=ref.getFromAddress()
  neighbors=[]
  for delta in range(-0x40,0x49,8):
   try:
    p=a.add(delta)
    v=mem.getLong(p)&0xffffffffffffffff
    target=lookup("%x"%v)
    neighbors.append({"relative":delta,"address":str(p),"value":"0x%x"%v,
                      "function":str(target.getEntryPoint()) if target and target.getEntryPoint()==sp.getAddress(v) else None})
   except Exception:pass
  refs=[]
  for r in getReferencesTo(a):
   if len(refs)>=48:break
   owner=getFunctionContaining(r.getFromAddress())
   refs.append({"from":str(r.getFromAddress()),"type":str(r.getReferenceType()),
                "owner":str(owner.getEntryPoint()) if owner else None})
  out.append({"address":str(a),"nearby_slots":neighbors,"slot_references":refs})
 return out
args=getScriptArgs()
if len(args)!=2 or args[1] not in SEEDS:raise ValueError("Expected output.json xp|win7")
out,platform=args
dec=DecompInterface()
dec.openProgram(currentProgram)
result={"platform":platform,"functions":[]}
for seed in SEEDS[platform]["functions"]+[SEEDS[platform]["shared"]]:
 fn=lookup(seed)
 if not fn:
  result["functions"].append({"seed":seed,"missing":True})
  continue
 result["functions"].append({"seed":seed,"entry":str(fn.getEntryPoint()),
                             "name":fn.getName(),"decompilation":decompile(fn,dec),
                             "table_refs":table_refs(fn)})
with open(out,"w") as f:json.dump(result,f,indent=2)
dec.dispose()
print("FECS table trace exported: "+out)
