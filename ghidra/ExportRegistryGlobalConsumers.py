# Bounded Ghidra exporter of xrefs to the class-registry global pointer.
# Usage: -postScript ExportRegistryGlobalConsumers.py output.json xp|win7
# NOTE: static xrefs; not proof of GP106 runtime dispatch.
import json
from ghidra.app.decompiler import DecompInterface

ROOTS={'xp':('0094b270','00117db0'),'win7':('007da840','0023c050')}
MAX_XREFS=180
MAX_FUNCTIONS=56
MAX_DECOMP_SIZE=0x2500
MAX_DECOMP_TEXT=16000

args=getScriptArgs()
if len(args)!=2 or args[1] not in ROOTS:
    raise ValueError('expected output.json xp|win7')
output,platform=args
global_address,registration_entry=ROOTS[platform]
space=currentProgram.getAddressFactory().getDefaultAddressSpace()
def A(s):
    return space.getAddress(int(s,16))
def section(a):
    b=currentProgram.getMemory().getBlock(a)
    return b.getName() if b else None
registry_global=A(global_address)
references=[]
owners={}
for ref in getReferencesTo(registry_global):
    from_addr=ref.getFromAddress()
    if section(from_addr)=='.pdata':continue
    fn=getFunctionContaining(from_addr)
    row={'source':str(from_addr),'kind':str(ref.getReferenceType()),
         'owner':str(fn.getEntryPoint()) if fn else None}
    references.append(row)
    if fn:
        entry=str(fn.getEntryPoint())
        owner=owners.setdefault(entry,{'entry':entry,'references':[]})
        owner['references'].append(row)
    if len(references)>=MAX_XREFS:break

# The actual register-class routine and small nearby xref-owning functions;
# do not sweep the driver or decompile unrelated functions.
sorted_owners=sorted(owners.values(),
                     key=lambda x:(-len(x['references']),x['entry']))
selected=sorted_owners[:MAX_FUNCTIONS]
if registration_entry not in set(x['entry'] for x in selected):
    selected.append(owners.get(registration_entry,{'entry':registration_entry,'references':[]}))
decompiler=DecompInterface()
decompiler.openProgram(currentProgram)
for item in selected:
    fn=getFunctionAt(A(item['entry']))
    if fn is None:
        item['status']='not_found'
        continue
    size=int(fn.getBody().getNumAddresses())
    item['size']=size
    if size>MAX_DECOMP_SIZE:
        item['status']='too_large'
        continue
    res=decompiler.decompileFunction(fn,10,monitor)
    if res.decompileCompleted() and res.getDecompiledFunction():
        code=str(res.getDecompiledFunction().getC())
        item['decompilation']=code[:MAX_DECOMP_TEXT]
        item['status']='ok'
        item['decompilation_truncated']=len(code)>MAX_DECOMP_TEXT
    else:
        item['status']='decompile_failed'
decompiler.dispose()
with open(output,'w') as dst:
    json.dump({'schema_version':1,'platform':platform,
      'registry_global':global_address,
      'registration_function':registration_entry,
      'incoming_global_references':references,
      'reference_owner_count':len(owners),
      'bounded_decompiled_owners':selected,
      'runtime_gp106_selection_proven':False,
      'patch_candidate':False,
      'caveat':'Only bounded global-pointer static references; not GPU runtime selection.'},
      dst,indent=2)
print('registry global %s: refs=%d owners=%d selected=%d'%(
       platform,len(references),len(owners),len(selected)))
