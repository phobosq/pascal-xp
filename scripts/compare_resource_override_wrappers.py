#!/usr/bin/env python3
import argparse,json
from pathlib import Path

def load(p): return json.loads(Path(p).read_text())

def sig(c):
    offs=[a.get("offset") for a in c.get("assignments",[])]
    shapes=[]
    for a in c.get("assignments",[]):
        s=a.get("target_shape") or {}
        shapes.append((s.get("size"),s.get("calls"),len(s.get("noncode_data_refs") or [])))
    return offs,shapes

def shape_similarity(a,b):
    ao,as_=sig(a); bo,bs_=sig(b)
    A=set(ao); B=set(bo)
    j=len(A&B)/max(len(A|B),1) if A or B else 0
    exact=1.0 if ao==bo else 0.0
    n=min(len(as_),len(bs_)); sh=0.0
    for x,y in zip(as_[:n],bs_[:n]):
        if None in x or None in y: continue
        sz=1-min(abs(x[0]-y[0])/max(x[0],y[0],1),1)
        ca=1-min(abs(x[1]-y[1])/max(x[1],y[1],1),1)
        dr=1-min(abs(x[2]-y[2])/max(x[2],y[2],1),1)
        sh += .6*sz+.2*ca+.2*dr
    sh = sh/max(n,1)
    return .45*exact+.25*j+.30*sh, exact,j,sh

ap=argparse.ArgumentParser()
ap.add_argument("--xp",required=True)
ap.add_argument("--win7",required=True)
ap.add_argument("--out",required=True)
args=ap.parse_args()

xp=load(args.xp).get("candidates",[])
w7=load(args.win7).get("candidates",[])
pairs=[]
for w in w7:
    best=None
    for x in xp:
        sc,ex,j,sh=shape_similarity(x,w)
        rec={"xp_entry":x.get("entry"),"win7_entry":w.get("entry"),"score":round(sc,6),
             "offset_exact":bool(ex),"offset_jaccard":round(j,4),"shape_similarity":round(sh,4),
             "xp_offsets":sig(x)[0],"win7_offsets":sig(w)[0],
             "xp_getterish":x.get("getterish_count"),"win7_getterish":w.get("getterish_count")}
        if best is None or rec["score"]>best["score"]: best=rec
    pairs.append(best)

unmatched=[]
for w,b in zip(w7,pairs):
    unmatched_score=1-(b["score"] if b else 0)
    unmatched.append({"win7_entry":w.get("entry"),"unmatched_score":round(unmatched_score,6),
                      "best_xp":b,"win7_offsets":sig(w)[0],
                      "getterish_count":w.get("getterish_count"),"score":w.get("score"),
                      "base_calls":[x.get("target") for x in w.get("base_calls",[])],
                      "assignments":[{"offset":a.get("offset"),"target":a.get("target"),
                                      "shape":a.get("target_shape")} for a in w.get("assignments",[])]})
unmatched.sort(key=lambda r:(-r["unmatched_score"],-(r["getterish_count"] or 0),r["win7_entry"]))

out={"schema_version":1,
     "matched_pairs":sorted([p for p in pairs if p],key=lambda r:-r["score"])[:80],
     "unmatched_win7_wrappers":unmatched[:80],
     "high_confidence_unmatched":[r for r in unmatched if r["unmatched_score"]>=0.45 and (r["getterish_count"] or 0)>=1][:30]}
Path(args.out).write_text(json.dumps(out,indent=2)+"\n")
print(json.dumps({"xp":len(xp),"win7":len(w7),
                  "high_confidence_unmatched":len(out["high_confidence_unmatched"]),
                  "top":out["high_confidence_unmatched"][:5]}))
