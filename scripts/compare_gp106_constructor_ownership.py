#!/usr/bin/env python3
import argparse,json,math
from pathlib import Path

def load(p): return json.loads(Path(p).read_text())

def owner_set_roots(d):
    return {o.get("entry") for o in d.get("owners",[]) if o.get("entry")}

def owner_set_parents(d):
    s=set()
    for ds in d.get("descriptor_sites",[]):
        for r in ds.get("direct_references",[]):
            if r.get("function_owner"): s.add(r["function_owner"])
        for n in ds.get("nearby_referenced_cells",[]):
            for r in n.get("references",[]):
                if r.get("function_owner"): s.add(r["function_owner"])
    for h in d.get("full_pointer_hits",[]):
        for r in h.get("references_to_pointer",[]):
            if r.get("function_owner"): s.add(r["function_owner"])
    return s

def shapes(c):
    out=[]
    for a in c.get("assignments",[]):
        s=a.get("target_shape") or {}
        out.append((s.get("size"),s.get("calls"),s.get("data_refs")))
    return out

def shape_sim(a,b):
    A=shapes(a); B=shapes(b)
    if not A or not B: return 0.0
    n=min(len(A),len(B)); score=0.0
    for x,y in zip(A[:n],B[:n]):
        if None in x or None in y: continue
        ss=1.0-min(abs(x[0]-y[0])/max(x[0],y[0],1),1.0)
        cs=1.0-min(abs(x[1]-y[1])/max(x[1],y[1],1),1.0)
        ds=1.0-min(abs(x[2]-y[2])/max(x[2],y[2],1),1.0)
        score+=(0.6*ss+0.2*cs+0.2*ds)
    return score/max(n,1)

def prox(c,owners):
    direct=set(c.get("direct_owners",[]))
    second={x.get("owner") for x in c.get("second_order",[]) if x.get("owner")}
    getter=set()
    for g in c.get("getter_incoming",[]): getter.update(g.get("owners",[]))
    hits={"direct":sorted(direct&owners),"second":sorted(second&owners),"getter":sorted(getter&owners)}
    score=(3*len(hits["direct"])+2*len(hits["getter"])+len(hits["second"]))
    return score,hits

ap=argparse.ArgumentParser()
for n in ["xp","win7","xp_roots","win7_roots","xp_parents","win7_parents"]: ap.add_argument("--"+n,required=True)
ap.add_argument("--out",required=True)
args=ap.parse_args()
xp=load(args.xp); w7=load(args.win7)
xo=owner_set_roots(load(args.xp_roots))|owner_set_parents(load(args.xp_parents))
wo=owner_set_roots(load(args.win7_roots))|owner_set_parents(load(args.win7_parents))
pairs=[]
for a in xp.get("candidates",[]):
    ao,ah=prox(a,xo)
    for b in w7.get("candidates",[]):
        bo,bh=prox(b,wo)
        A=set(a.get("offsets",[])); B=set(b.get("offsets",[]))
        if not A or not B: continue
        exact=1.0 if a.get("offsets")==b.get("offsets") else 0.0
        j=len(A&B)/max(len(A|B),1)
        fs=1.0-min(abs((a.get("function_size") or 0)-(b.get("function_size") or 0))/max(a.get("function_size") or 1,b.get("function_size") or 1),1.0)
        sh=shape_sim(a,b)
        score=0.30*exact+0.20*j+0.20*sh+0.10*fs+0.10*min(ao,3)/3+0.10*min(bo,3)/3
        if exact or score>=0.58 or ao or bo:
            pairs.append({"xp_entry":a.get("entry"),"win7_entry":b.get("entry"),
                          "score":round(score,6),"offset_exact":bool(exact),"offset_jaccard":round(j,4),
                          "shape_similarity":round(sh,4),"size_similarity":round(fs,4),
                          "xp_fecs_proximity":ao,"win7_fecs_proximity":bo,
                          "xp_hits":ah,"win7_hits":bh,
                          "offsets_xp":a.get("offsets"),"offsets_win7":b.get("offsets")})
pairs.sort(key=lambda x:(-x["score"],-(x["xp_fecs_proximity"]+x["win7_fecs_proximity"]),x["xp_entry"],x["win7_entry"]))
out={"schema_version":1,"xp_fecs_owners":sorted(xo),"win7_fecs_owners":sorted(wo),
     "ranked_pairs":pairs[:250],
     "top_actionable":[p for p in pairs if p["xp_fecs_proximity"] or p["win7_fecs_proximity"]][:40],
     "caveat":"Ranking is structural/static evidence, not proof of GP106 runtime selection."}
Path(args.out).write_text(json.dumps(out,indent=2)+"\n")
print(json.dumps({"pairs":len(pairs),"actionable":len(out["top_actionable"]),
                  "top":out["ranked_pairs"][:3]}))
