#!/usr/bin/env python3
"""Run the exact portable SIGKILL drills and audit test-only fault controls.

No root, network listener, account/configuration changes or service installation.
All generated state belongs to the test executables' private temporary folders.
"""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess

parser=argparse.ArgumentParser()
wire=parser.add_mutually_exclusive_group(required=True)
wire.add_argument('--wire-artifacts')
wire.add_argument('--wire-test')
witness=parser.add_mutually_exclusive_group(required=True)
witness.add_argument('--witness-artifacts')
witness.add_argument('--witness-test')
args=parser.parse_args()

def executable(metadata,explicit,target):
    if explicit:
        return Path(explicit).resolve(strict=True)
    matches=[]
    for line in Path(metadata).read_text().splitlines():
        try:
            item=json.loads(line)
        except json.JSONDecodeError:
            continue
        if item.get('reason')=='compiler-artifact' and item.get('target',{}).get('name')==target and item.get('executable'):
            matches.append(Path(item['executable']).resolve(strict=True))
    if len(matches)!=1:
        parser.error('expected one test executable for '+target)
    return matches[0]

def run_exact(binary,test):
    listing=subprocess.run([str(binary),'--list','--exact',test],capture_output=True,text=True,check=True,timeout=10)
    names=[line.removesuffix(': test') for line in listing.stdout.splitlines() if line.endswith(': test')]
    if names!=[test]:
        parser.error('exact required test is missing: '+test)
    child=subprocess.Popen([str(binary),'--exact',test,'--nocapture','--test-threads=1'],start_new_session=True)
    try:
        result=child.wait(timeout=90)
    except BaseException:
        try:
            os.killpg(child.pid,signal.SIGKILL)
        except ProcessLookupError:
            pass
        child.wait(timeout=10)
        raise
    if result:
        raise SystemExit(result)

wire_test=executable(args.wire_artifacts,args.wire_test,'tl_collator_wire')
witness_test=executable(args.witness_artifacts,args.witness_test,'process_crash')
markers=[b'TL_TEST_TAPE_CRASH_STAGE',b'TL_TAPE_CRASH_READY',b'TL_TEST_WITNESS_PROCESS_PATH',b'TL_WITNESS_DURABLE_READY']
for name in ('witnessctl','witness-export','witness-ssh-gate'):
    binary=witness_test.parent.parent/name
    contents=binary.read_bytes()
    if any(marker in contents for marker in markers):
        parser.error('test-only fault-control marker present in service executable: '+name)
print('Service executables: test-only fault-control markers absent.',flush=True)
run_exact(wire_test,'durable::crash_tests::sigkill_at_each_durable_boundary_recovers_the_exact_signed_prefix')
run_exact(witness_test,'sigkill_after_remote_commit_or_signing_requires_explicit_verified_recovery')
print('Process-crash drills passed; no machine or storage power-loss claim.',flush=True)
