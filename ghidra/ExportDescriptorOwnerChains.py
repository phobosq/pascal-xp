# Focused Ghidra exporter: descriptor header owners and immediate callers.
# -postScript ExportDescriptorOwnerChains.py parents.json out.json xp|win7
import json
from ghidra.app.decompiler import DecompInterface
space=currentProgram.getAddressFactory().getDefaultAddressSpace()
mem=currentProgram.getMemory()
listing=currentProgram.getListing()
def A(s):return space.getAddress(int(str(s),16))
def section(a):
 b=mem.getBlock(a);return b.getName() if b else None
def function(a):return getFunctionAt(a) or getFunctionContaining(a)
def refs(a):
 out=[]
 for r in getReferencesTo(a):
  src=r.getFromAddress()
  if section(src)=='.pdata':continue
  f=function(src)
  out.append({'source':str(src),'type':str(r.getReferenceType()),'section':section(src),'owner':str(f.getEntryPoint()) if f else None})
  if len(out)>=24:break
 return out
def cells(a):
 out=[];off=int(a.getOffset());sec=section(a)
 for delta in range(-0x20,0x61,4):
  p=A('%x'%(off+delta))
  if section(p)!=sec:continue
  try:
   u=int(mem.getInt(p))&0xffffffff;row={'relative':delta,'u32':'0x%x'%u}
   if delta%8==0:
    v=int(mem.getLong(p))&0xffffffffffffffff;target=A('%x'%v)
    if section(target):row['pointer']={'value':'0x%x'%v,'section':section(target)}
   out.append(row)
  except:pass
 return out
def decomp(f,dec):
 if not f or int(f.getBody().getNumAddresses())>0x900:return None
 r=dec.decompileFunction(f,12,monitor)
 return str(r.getDecompiledFunction().getC())[:16000] if r.decompileCompleted() and r.getDecompiledFunction() else None
def outgoing(f):
 out=[];it=listing.getInstructions(f.getBody(),True)
 while it.hasNext():
  ins=it.next()
  for r in ins.getReferencesFrom():
   if not(r.getReferenceType().isCall() or r.getReferenceType().isData()):continue
   dest=r.getToAddress()
   out.append({'site':str(ins.getAddress()),'to':str(dest),'type':str(r.getReferenceType()),'section':section(dest)})
   if len(out)>=80:return out
 return out
args=getScriptArgs()
if len(args)!=3 or args[2] not in ('xp','win7'):raise ValueError('expected parents.json out.json xp|win7')
parent_path,out,platform=args;parents=json.load(open(parent_path));headers={}
for site in parents.get('descriptor_sites',[]):
 for cell in site.get('nearby_referenced_cells',[]):
  for ref in cell.get('references',[]):
   owner=ref.get('function_owner')
   if owner:headers.setdefault(owner,{}).setdefault(cell['address'],set()).add(site['site'])
 for ref in site.get('direct_references',[]):
  owner=ref.get('function_owner')
  if owner:headers.setdefault(owner,{}).setdefault(site['site'],set()).add(site['site'])
dec=DecompInterface();dec.openProgram(currentProgram);rows=[]
for entry,head in sorted(headers.items()):
 f=function(A(entry))
 if not f:continue
 incoming=refs(f.getEntryPoint());callers={r['owner'] for r in incoming if r.get('owner') and r['owner']!=entry}
 chain=[]
 for caller in sorted(callers)[:10]:
  cf=function(A(caller))
  if cf:chain.append({'entry':caller,'size':int(cf.getBody().getNumAddresses()),'incoming':refs(cf.getEntryPoint()),'outgoing':outgoing(cf),'decompilation':decomp(cf,dec)})
 rows.append({'entry':entry,'size':int(f.getBody().getNumAddresses()),'headers':[{'address':h,'matched_descriptor_sites':sorted(v),'cells':cells(A(h)),'references':refs(A(h))} for h,v in sorted(head.items())],'incoming':incoming,'outgoing':outgoing(f),'decompilation':decomp(f,dec),'callers':chain})
dec.dispose()
with open(out,'w') as h:json.dump({'schema_version':1,'platform':platform,'owners':rows,'caveat':'Static xrefs do not prove GP106 runtime selection.'},h,indent=2)
print('descriptor header owners traced: %d'%len(rows))
