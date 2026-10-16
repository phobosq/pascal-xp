#!/usr/bin/env python3
import json
from pathlib import Path

R=Path("work/reports")
def load(name):
    p=R/name
    return json.loads(p.read_text()) if p.exists() else {}

xp_par=load("xp_fecs_descriptor_parents.json")
w7_par=load("win7_fecs_descriptor_parents.json")
xp_roots=load("xp_fecs_table_roots.json")
w7_roots=load("win7_fecs_table_roots.json")
shape=load("xp_vs_win7_callback_shapes.json")
slots=load("xp_vs_win7_fecs_slot_assignments.json")
status=load("xp_vs_win7_fecs_status_flow.json")

def unique_owners(obj):
    out=set()
    for d in obj.get("descriptor_sites",[]):
        for r in d.get("direct_references",[]):
            if r.get("function_owner"): out.add(r["function_owner"])
        for c in d.get("nearby_referenced_cells",[]):
            for r in c.get("references",[]):
                if r.get("function_owner"): out.add(r["function_owner"])
    for h in obj.get("full_pointer_hits",[]):
        for r in h.get("references_to_pointer",[]):
            if r.get("function_owner"): out.add(r["function_owner"])
    return sorted(out)

def root_owners(obj):
    out=set()
    for r in obj.get("roots",[]):
        for x in r.get("references",[]):
            if x.get("owner"): out.add(x["owner"])
        for n in r.get("neighborhood",[]):
            for x in n.get("references",[]):
                if x.get("owner"): out.add(x["owner"])
    for o in obj.get("owners",[]):
        if o.get("entry"): out.add(o["entry"])
    return sorted(out)

xp_po=unique_owners(xp_par); w7_po=unique_owners(w7_par)
xp_ro=root_owners(xp_roots); w7_ro=root_owners(w7_roots)
top_shapes=(shape.get("ranked_pairs") or [])[:10]

next_actions=[]
if w7_po and not xp_po:
    next_actions.append({
      "priority":1,
      "reason":"Win7 descriptor parents resolve to code owners while XP does not.",
      "action":"Trace Win7 descriptor-owner functions to structural analogues in XP, then follow their DATA refs back to XP registration arrays.",
      "targets":{"win7":w7_po[:12],"xp":[]}
    })
if xp_ro or w7_ro:
    next_actions.append({
      "priority":2,
      "reason":"Static owners were found around real FECS table roots.",
      "action":"Intersect FECS table-root owners with GP106/GP10x registration and architecture-selection functions.",
      "targets":{"xp":xp_ro[:12],"win7":w7_ro[:12]}
    })
if top_shapes:
    next_actions.append({
      "priority":3,
      "reason":"Structural callback initializer analogues remain useful as secondary evidence only.",
      "action":"Use top callback-shape pairs only when one side is linked to a confirmed FECS/GP106 owner.",
      "targets":{"pairs":[[p.get("xp_entry"),p.get("win7_entry"),p.get("shape_similarity")] for p in top_shapes[:8]]}
    })

summary={
 "schema_version":1,
 "conclusions":{
   "xp_descriptor_parent_owners":xp_po,
   "win7_descriptor_parent_owners":w7_po,
   "xp_table_root_owners":xp_ro,
   "win7_table_root_owners":w7_ro,
   "callback_shape_top":top_shapes,
   "status_flow_present":bool(status),
   "slot_comparison_present":bool(slots),
 },
 "next_actions":sorted(next_actions,key=lambda x:x["priority"]),
 "caveats":[
   "Static DATA/CALL references do not prove GP106 runtime selection.",
   "Callback structural similarity is not ABI or ownership proof.",
   "Do not patch until a concrete GP106 path divergence is tied to a propagated failure status."
 ]
}
(R/"analysis_summary.json").write_text(json.dumps(summary,indent=2)+"\n")

lines=["# Pascal XP automated analysis summary",""]
lines += [f"- XP descriptor-parent owners: {len(xp_po)}",f"- Win7 descriptor-parent owners: {len(w7_po)}",
          f"- XP FECS table-root owners: {len(xp_ro)}",f"- Win7 FECS table-root owners: {len(w7_ro)}",
          f"- Ranked callback-shape pairs: {len(shape.get('ranked_pairs') or [])}",""]
if next_actions:
    lines.append("## Next actions")
    for a in sorted(next_actions,key=lambda x:x["priority"]):
        lines += [f"{a['priority']}. **{a['reason']}**",f"   - {a['action']}"]
lines += ["","## Caveats"]+[f"- {x}" for x in summary["caveats"]]
(R/"analysis_summary.md").write_text("\n".join(lines)+"\n")
print(json.dumps({"xp_parent_owners":len(xp_po),"win7_parent_owners":len(w7_po),
                  "xp_root_owners":len(xp_ro),"win7_root_owners":len(w7_ro),
                  "next_actions":len(next_actions)}))
