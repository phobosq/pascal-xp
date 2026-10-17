# Ghidra Jython, bounded class registration state / consumer trace.
# -postScript ExportClassRegistryLookup.py output.json xp|win7
# Anchors are only valid for SHA-guarded XP/Win7 368.81 driver inputs.
import json
from ghidra.app.decompiler import DecompInterface

ENTRY={'xp':'00117db0','win7':'0023c050'}
MAX_CHILDREN=8
MAX_STATE_GLOBALS=24
MAX_GLOBAL_XREFS=40
MAX_CONSUMER_DECOMP=8

args=getScriptArgs()
if len(args)!=2 or args[1] not in ENTRY:
    raise ValueError('expected output.json xp|win7')
output,platform=args
space=currentProgram.getAddressFactory().getDefaultAddressSpace()
mem=currentProgram.getMemory()
listing=currentProgram.getListing()
def addr(value):
    return space.getAddress(int(str(value),16))
def section(a):
    b=mem.getBlock(a)
    return b.getName() if b else None
def func(a):
    return getFunctionAt(a) or getFunctionContaining(a)
def inbound(a,limit):
    rows=[]
    for r in getReferencesTo(a):
        src=r.getFromAddress()
        if section(src)=='.pdata':continue
        owner=func(src)
        rows.append({'source':str(src),'type':str(r.getReferenceType()),
                     'owner':str(owner.getEntryPoint()) if owner else None,
                     'section':section(src)})
        if len(rows)>=limit:break
    return rows
def refs_from(f,limit):
    rows=[]
    it=listing.getInstructions(f.getBody(),True)
    while it.hasNext():
        ins=it.next()
        for ref in ins.getReferencesFrom():
            dest=ref.getToAddress()
            typ=ref.getReferenceType()
            if not(typ.isCall() or typ.isData() or typ.isRead() or typ.isWrite()):
                continue
            rows.append({'source':str(ins.getAddress()),'target':str(dest),
                         'type':str(typ),'section':section(dest),
                         'call':bool(typ.isCall()),'read':bool(typ.isRead()),
                         'write':bool(typ.isWrite())})
            if len(rows)>=limit:return rows
    return rows

dec=DecompInterface()
dec.openProgram(currentProgram)
def decompile(f):
    if f is None:return {'status':'not_found'}
    size=int(f.getBody().getNumAddresses())
    if size>0x2000:return {'status':'too_large','size':size}
    result=dec.decompileFunction(f,12,monitor)
    if not(result.decompileCompleted() and result.getDecompiledFunction()):
        return {'status':'decompile_failed','size':size}
    return {'status':'ok','size':size,
            'decompilation':str(result.getDecompiledFunction().getC())[:18000]}

registry=addr(ENTRY[platform])
root=getFunctionAt(registry)
if root is None:
    raise ValueError('registration function missing at '+ENTRY[platform])
root_analysis=decompile(root)
root_out=refs_from(root,256)
children=[]
seen=set()
for row in root_out:
    if not row['call']:continue
    callee=getFunctionAt(addr(row['target']))
    if callee is None:continue
    key=str(callee.getEntryPoint())
    if key in seen or key==str(registry):continue
    seen.add(key)
    child={'entry':key,'called_at':row['source']}
    child.update(decompile(callee))
    child['outgoing']=refs_from(callee,128)
    children.append(child)
    if len(children)>=MAX_CHILDREN:break

# Direct global references plus one bounded hop through registry callees.
state={}
origins=[('registry',root_out)]+[(c['entry'],c.get('outgoing',[]))
                                for c in children]
for origin,refs in origins:
    for row in refs:
        sec=row['section'] or ''
        if row['call'] or not sec or sec in ('.text','.pdata'):
            continue
        key=row['target']
        if key not in state and len(state)>=MAX_STATE_GLOBALS:continue
        state.setdefault(key,{'address':key,'section':sec,
                               'producers':[],'references':[]})['producers'].append(
            {'entry':origin,'source':row['source'],'type':row['type']})
candidates={}
for key,value in sorted(state.items()):
    references=inbound(addr(key),MAX_GLOBAL_XREFS)
    value['references']=references
    for ref in references:
        owner=ref['owner']
        if not owner or owner==str(registry) or owner in seen:continue
        typ=ref['type'].upper()
        if 'READ' not in typ and 'DATA' not in typ:continue
        candidate=candidates.setdefault(owner,{'entry':owner,
                    'state_addresses':[],'xref_sites':[]})
        if key not in candidate['state_addresses']:
            candidate['state_addresses'].append(key)
        candidate['xref_sites'].append(ref['source'])
ranked=sorted(candidates.values(),
              key=lambda c:(-len(c['state_addresses']),c['entry']))
for item in ranked[:MAX_CONSUMER_DECOMP]:
    item.update(decompile(getFunctionAt(addr(item['entry']))))
dec.dispose()
with open(output,'w') as fp:
    json.dump({'schema_version':1,'platform':platform,
       'registration_entry':ENTRY[platform],
       'registration_function':{
           'entry':ENTRY[platform],
           'incoming':inbound(registry,100),
           'outgoing':root_out,
           'analysis':root_analysis},
       'direct_callees':children,
       'candidate_global_references':list(state.values()),
       'ranked_lookup_candidates':ranked,
       'runtime_gp106_selection_proven':False,
       'patch_candidate':False,
       'caveat':'Static bounded xrefs only. Reads do not prove GP106 runtime selection.'},
       fp,indent=2)
print('registry %s: callees=%d state=%d candidates=%d'%(
      platform,len(children),len(state),len(ranked)))
