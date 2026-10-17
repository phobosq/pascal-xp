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
ctor=load("xp_vs_win7_gp106_constructor_ownership.json")
chains=load("xp_vs_win7_descriptor_owner_chains.json")
sec2=load("sec2_wrapper_audit.json")
lifecycle=load("registration_lifecycle_audit.json")
registration=load("xp_vs_win7_registration_followup.json")
registry=load("xp_vs_win7_class_registry_lookup.json")
registry_consumers=load("xp_vs_win7_registry_global_consumers.json")
xp_fecs_tables=load("xp_fecs_root_registration.json")
win7_fecs_tables=load("win7_fecs_root_registration.json")

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
top_ctor=(ctor.get("top_actionable") or [])[:10]

next_actions=[]
if registry_consumers:
    likely={
      side:registry_consumers.get(side,{}).get("positive_candidates",[])[:6]
      for side in ("xp","win7")
    }
    if likely["xp"] or likely["win7"]:
        next_actions.append({
            "priority":1,
            "reason":"Bounded class-registry global consumer decompilation identified candidate virtual dispatch.",
            "action":"Verify actual class-selecting conditions, candidate PCI/GPU ties, and status propagation; generic RM_ASSERT is deprioritized.",
            "targets":likely
        })

if registry and (registry.get("xp",{}).get("top_consumers") or registry.get("win7",{}).get("top_consumers")):
    next_actions.append({
      "priority":1,
      "reason":"Static class-registry state consumers identified; actual GP106 class selection still unproven.",
      "action":"Trace top bounded registry global-data consumers toward an observed class lookup/branch and propagated status. Do not equate class index with PCI device ID.",
      "targets":{"xp":registry.get("xp",{}).get("top_consumers",[])[:5],
                 "win7":registry.get("win7",{}).get("top_consumers",[])[:5]}})

unmatched=chains.get("ranked_unmatched_win7_headers") or []
if unmatched:
    p=unmatched[0]
    next_actions.append({"priority":1,"reason":"Descriptor header owner needs GP106 class-selection verification.",
      "action":"Trace incoming registration callers and branch conditions before proposing a patch.",
      "targets":{"win7":p.get("win7_entry"),"xp_candidates":p.get("best_xp_matches",[])}})
if top_ctor:
    p=top_ctor[0]
    next_actions.append({
      "priority":1,
      "reason":"A GP106-like constructor pair ranks highest after FECS-owner proximity and structural matching.",
      "action":"Deep-trace the top XP/Win7 constructor pair and its getter targets; prefer this over broad scans.",
      "targets":{"xp":p.get("xp_entry"),"win7":p.get("win7_entry"),"score":p.get("score"),
                 "xp_fecs_proximity":p.get("xp_fecs_proximity"),"win7_fecs_proximity":p.get("win7_fecs_proximity")}
    })
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
   "gp106_constructor_top":top_ctor,
   "descriptor_header_owner_ranking":unmatched[:10],
   "sec2_wrapper_audit":sec2,
   "registration_lifecycle_audit":lifecycle,
   "registration_counterparts":registration,
   "class_registry_lookup":registry,
   "registry_global_dispatch_candidates":registry_consumers,
   "xp_fecs_table_registration":xp_fecs_tables,
   "win7_fecs_table_registration":win7_fecs_tables,
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
          f"- Ranked callback-shape pairs: {len(shape.get('ranked_pairs') or [])}",
          f"- Ranked GP106-like constructor pairs: {len(ctor.get('ranked_pairs') or [])}",
          f"- Descriptor owner chains ranked: {len(unmatched)}",
          f"- SEC2 audit classification: {sec2.get('semantic_classification', 'not available')}",
          f"- XP sampled FECS-root initializer/data links: {len(xp_fecs_tables.get('initializer_data_links', []))}",
          f"- Win7 sampled FECS-root initializer/data links: {len(win7_fecs_tables.get('initializer_data_links', []))}",
          f"- XP registry candidate lookup consumers: {registry.get('xp', {}).get('candidate_consumer_count', 0)}",
          f"- XP registry global dispatch candidates: {len(registry_consumers.get('xp', {}).get('positive_candidates', []))}",
          f"- Win7 registry global dispatch candidates: {len(registry_consumers.get('win7', {}).get('positive_candidates', []))}",
          f"- Win7 registry candidate lookup consumers: {registry.get('win7', {}).get('candidate_consumer_count', 0)}",
          f"- Registration index/header matches: {registration.get('matched_indices', 0)}/{registration.get('total_counterparts', 0)}",
          f"- Registration callback slot +0x4c8 parity: {lifecycle.get('callback_slot_parity_confirmed', False)}",
          f"- Seven OS helper semantics paired XP/Win7: {lifecycle.get('post_registration', {}).get('semantic_parity_confirmed', False)}",
          f"- Confirmed actionable constructor pairs: {len(ctor.get('top_actionable') or [])}",
          f"- Two-sided static proximity hypotheses: {len(ctor.get('two_sided_proximity_hypotheses') or [])}",
          f"- One-sided static proximity hypotheses: {len(ctor.get('one_sided_proximity_hypotheses') or [])}",""]
if next_actions:
    lines.append("## Next actions")
    for a in sorted(next_actions,key=lambda x:x["priority"]):
        lines += [f"{a['priority']}. **{a['reason']}**",f"   - {a['action']}"]
lines += ["","## Caveats"]+[f"- {x}" for x in summary["caveats"]]
(R/"analysis_summary.md").write_text("\n".join(lines)+"\n")
print(json.dumps({"xp_parent_owners":len(xp_po),"win7_parent_owners":len(w7_po),
                  "xp_root_owners":len(xp_ro),"win7_root_owners":len(w7_ro),
                  "next_actions":len(next_actions)}))
