# Ghidra Jython: -postScript ExportRegistrationFollowup.py manifest.json output.json xp|win7
# Focused decompilation only; no proprietary binaries or firmware exported.
import json
from ghidra.app.decompiler import DecompInterface

args = getScriptArgs()
if len(args) not in (3,4) or args[2] not in ('xp','win7'):
    raise ValueError('expected manifest.json output.json xp|win7 [selection.json]')
manifest_path, output_path, platform = args[:3]
manifest = json.load(open(manifest_path))
entries = manifest['platforms'][platform]['focus_addresses']
if len(args) == 4:
    selection = json.load(open(args[3]))
    if selection.get('platform') != platform:
        raise ValueError('RVA selection platform mismatch')
    wanted = selection.get('focus_addresses')
    if not isinstance(wanted, list) or len(wanted) != len(set(wanted)):
        raise ValueError('invalid RVA selection')
    if any(entry not in entries for entry in wanted):
        raise ValueError('RVA selection outside manifest')
    entries = wanted
space = currentProgram.getAddressFactory().getDefaultAddressSpace()
mem = currentProgram.getMemory()
listing = currentProgram.getListing()

def addr(value):
    return space.getAddress(int(str(value),16))

def block_name(a):
    b = mem.getBlock(a)
    return b.getName() if b else None

def refs_to(a):
    rows=[]
    for r in getReferencesTo(a):
        src=r.getFromAddress()
        f=getFunctionContaining(src)
        rows.append({'source':str(src),'type':str(r.getReferenceType()),
                     'owner':str(f.getEntryPoint()) if f else None})
        if len(rows)>=80:break
    return rows

def refs_from(f):
    rows=[]
    insns=listing.getInstructions(f.getBody(),True)
    while insns.hasNext():
        insn=insns.next()
        for r in insn.getReferencesFrom():
            typ=r.getReferenceType()
            if not (typ.isCall() or typ.isData()):continue
            dest=r.getToAddress()
            rows.append({'source':str(insn.getAddress()),'target':str(dest),
                         'type':str(typ),'target_section':block_name(dest)})
            if len(rows)>=120:return rows
    return rows

dec=DecompInterface()
dec.openProgram(currentProgram)
rows=[]
for entry in entries:
    a=addr(entry)
    f=getFunctionAt(a)
    if not f:
        rows.append({'entry':entry,'status':'missing_function'})
        continue
    size=int(f.getBody().getNumAddresses())
    code=None
    status='too_large'
    if size<=0x2000:
        res=dec.decompileFunction(f,20,monitor)
        if res.decompileCompleted() and res.getDecompiledFunction():
            code=str(res.getDecompiledFunction().getC())[:24000]
            status='ok'
        else:status='decompile_failed'
    rows.append({'entry':entry,'status':status,'size':size,'decompilation':code,
                 'incoming':refs_to(a),'outgoing':refs_from(f)})
dec.dispose()
with open(output_path,'w') as out:
    json.dump({'schema_version':1,'platform':platform,'targets':rows,
               'caveat':'Static decompilation; not evidence of runtime GP106 dispatch.'},out,indent=2)
print('registration followup %s: %d targets'%(platform,len(rows)))
