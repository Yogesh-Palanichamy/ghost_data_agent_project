#!/usr/bin/env python3
"""Public-sample evaluation and output contract checks."""
import csv, json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import main as agent

root=agent.ROOT
requests=agent.read_csv(agent.DATA/"sample_deletion_requests.csv")
expected={r["case_id"]:r for r in agent.read_csv(agent.DATA/"sample_output.csv")}
identities=agent.read_csv(agent.DATA/"user_identities.csv")
audits=agent.read_csv(agent.DATA/"user_audit_log.csv")
activities=agent.read_csv(agent.DATA/"system_activity.csv")
observations,manifest=agent.load_evidence()
observations.extend(agent.activity_link_observations(activities))
observations.extend(agent.enrich_documents_from_identity_links(observations,activities))
_,case_users=agent.build_identity_maps(requests,identities,audits)
status_correct=0; exact_steps=0; fields_total=0; fields_correct=0; sequence_correct=0; step_exact_correct=0; step_positions=0
rows=[]
for req in requests:
    status,steps=agent.steps_for_case(req,observations,identities,audits,case_users.get(req["case_id"]),activities)
    gold=expected[req["case_id"]]
    gs=json.loads(gold["steps_json"])
    status_ok=status==gold["deletion_status"]
    status_correct+=status_ok
    pred_norm=[{k:s.get(k) for k in ["step_no","phase","system_id","resource_id","operation","state","evidence_id"]} for s in steps]
    exact=pred_norm==gs
    exact_steps+=exact
    if len(pred_norm)==len(gs):
        sequence_correct+=all(p.get("operation")==g.get("operation") and p.get("phase")==g.get("phase") for p,g in zip(pred_norm,gs))
    for i in range(max(len(pred_norm),len(gs))):
        step_positions+=1
        p_step=pred_norm[i] if i<len(pred_norm) else {}
        g_step=gs[i] if i<len(gs) else {}
        step_exact_correct += p_step==g_step
        p=pred_norm[i] if i<len(pred_norm) else {}
        g=gs[i] if i<len(gs) else {}
        for k in ["step_no","phase","system_id","resource_id","operation","state","evidence_id"]:
            fields_total+=1; fields_correct+=p.get(k)==g.get(k)
    rows.append((req["case_id"],status,len(steps),gold["deletion_status"],len(gs),status_ok,exact))
print(f"Sample status accuracy: {status_correct}/{len(requests)} = {status_correct/len(requests):.1%}")
print(f"Exact steps rows: {exact_steps}/{len(requests)} = {exact_steps/len(requests):.1%}")
print(f"Step-object accuracy: {step_exact_correct}/{step_positions} = {step_exact_correct/step_positions:.1%}")
print(f"Field accuracy: {fields_correct}/{fields_total} = {fields_correct/fields_total:.1%}")
print(f"Sequence accuracy: {sequence_correct}/{len(requests)} = {sequence_correct/len(requests):.1%}")
for r in rows: print(*r)
