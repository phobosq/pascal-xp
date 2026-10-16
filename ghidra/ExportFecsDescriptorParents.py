# Ghidra headless: trace registration descriptor arrays referencing FECS table consumers.
# Usage: -postScript ExportFecsDescriptorParents.py <output.json> <xp|win7>
# Static pointers and references do not prove GP106 runtime selection.
import json

SITES = {
    "xp": [
        "008475a0", "008475d8", "00847830", "00847868",
        "00847ac0", "00847af8", "00847fe0", "00848018",
        "00848270", "008482a8", "00848500", "00848538",
    ],
    "win7": [
        "006542a0", "006542d8", "00654ce0", "00654d18",
        "00652298", "00651048", "00652238", "00652758", "00652f08",
    ],
}
RADIUS = 0x200
MAX_POINTER_MATCHES = 512
MAX_REFERENCES = 40

space = currentProgram.getAddressFactory().getDefaultAddressSpace()
mem = currentProgram.getMemory()

def addr(x):
    return space.getAddress(int(x, 16) if isinstance(x, str) else int(x))

def block_name(a):
    b = mem.getBlock(a)
    return b.getName() if b else None

def function_owner(a):
    f = getFunctionContaining(a)
    return str(f.getEntryPoint()) if f else None

def refs_to(a):
    result = []
    for ref in getReferencesTo(a):
        src = ref.getFromAddress()
        sec = block_name(src)
        if sec == '.pdata':
            continue
        result.append({
            'source': str(src), 'type': str(ref.getReferenceType()),
            'section': sec, 'function_owner': function_owner(src),
        })
        if len(result) >= MAX_REFERENCES:
            break
    return result

def read_ptr(a):
    try:
        v = int(mem.getLong(a)) & 0xffffffffffffffff
        dest = addr(v)
        b = mem.getBlock(dest)
        return {'value': '0x%x' % v, 'target_section': b.getName() if b else None,
                'target_function': function_owner(dest) if b else None}
    except Exception:
        return None

def window(base, radius):
    result = []
    center = int(base.getOffset())
    sec = block_name(base)
    for offset in range(center-radius, center+radius+1, 8):
        a = addr(offset)
        if block_name(a) != sec:
            continue
        rr = refs_to(a)
        if rr:
            result.append({'address': str(a), 'relative': offset-center,
                           'pointer': read_ptr(a), 'references': rr})
    return result

def data_pointer_hits(targets):
    # Search aligned full 64-bit pointers to the vicinity of each descriptor.
    hits = []
    for block in mem.getBlocks():
        if not block.isInitialized() or block.isExecute() or block.getName() == '.pdata':
            continue
        start = int(block.getStart().getOffset())
        end = int(block.getEnd().getOffset())
        for off in range((start+7)&~7, end-7+1, 8):
            a = addr(off)
            try:
                v = int(mem.getLong(a)) & 0xffffffffffffffff
            except Exception:
                continue
            matched = [t for t in targets if abs(v-t) <= RADIUS]
            if not matched:
                continue
            hits.append({'address': str(a), 'section': block.getName(),
                         'value': '0x%x' % v,
                         'matched_sites': ['0x%x' % t for t in matched],
                         'references_to_pointer': refs_to(a)})
            if len(hits) >= MAX_POINTER_MATCHES:
                return hits, True
    return hits, False

args = getScriptArgs()
if len(args) != 2 or args[1] not in SITES:
    raise ValueError('expected output.json xp|win7')
output, platform = args
sites = [addr(s) for s in SITES[platform]]
site_details = []
for site in sites:
    site_details.append({
        'site': str(site), 'section': block_name(site),
        'pointer': read_ptr(site), 'direct_references': refs_to(site),
        'nearby_referenced_cells': window(site, RADIUS),
    })
pointer_hits, truncated = data_pointer_hits([int(s.getOffset()) for s in sites])
with open(output, 'w') as f:
    json.dump({'schema_version': 1, 'platform': platform,
               'caveat': 'Static DATA references and nearby pointers are not proof of GP106 runtime selection.',
               'descriptor_sites': site_details,
               'full_pointer_hits': pointer_hits,
               'pointer_hits_truncated': truncated}, f, indent=2)
print('FECS descriptor sites: %d pointer hits: %d' % (len(site_details), len(pointer_hits)))
