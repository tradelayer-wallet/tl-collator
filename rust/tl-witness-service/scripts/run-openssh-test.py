#!/usr/bin/env python3
"""Run only the synthetic loopback SSH test in a private mount namespace.

Requires root for the namespace and sshd privilege separation. Does not install
packages, modify host accounts/configuration or start a system service.
"""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile

parser=argparse.ArgumentParser()
parser.add_argument('--sshd',default='/usr/sbin/sshd')
source=parser.add_mutually_exclusive_group(required=True)
source.add_argument('--artifacts',help='cargo --message-format=json output')
source.add_argument('--test-binary',help='verified relocated openssh test executable')
args=parser.parse_args()
if os.geteuid()!=0:
    parser.error('run this test launcher with sudo; the host account database is not modified')
if args.test_binary:
    test=Path(args.test_binary).resolve(strict=True)
else:
    executables=[]
    for line in Path(args.artifacts).read_text().splitlines():
        try:
            item=json.loads(line)
        except json.JSONDecodeError:
            continue
        if item.get('reason')=='compiler-artifact' and item.get('target',{}).get('name')=='openssh' and item.get('executable'):
            executables.append(Path(item['executable']).resolve())
    if len(executables)!=1:
        parser.error('expected exactly one openssh integration-test executable')
    test=executables[0]
binary_dir=test.parent.parent
daemon=Path(args.sshd).resolve(strict=True)
for binary in (test,daemon,*[binary_dir/name for name in ('witnessctl','witness-export','witness-ssh-gate')]):
    if not binary.is_file():
        parser.error('missing test artifact: '+str(binary))
required_test='real_openssh_recovery_and_authorization'
listing=subprocess.run([str(test),'--list','--ignored','--exact',required_test],capture_output=True,text=True,check=True,timeout=10)
names=[line.removesuffix(': test') for line in listing.stdout.splitlines() if line.endswith(': test')]
if names!=[required_test]:
    parser.error('exact required OpenSSH test is missing')
with tempfile.TemporaryDirectory(prefix='tl-openssh-namespace-') as temporary:
    fixture=Path(temporary)
    passwd=Path('/etc/passwd').read_text()
    if not any(line.startswith('sshd:') for line in passwd.splitlines()):
        passwd+='sshd:x:65534:65534:synthetic privilege separation:/run/sshd:/usr/sbin/nologin\n'
    (fixture/'passwd').write_text(passwd)
    (fixture/'run/sshd').mkdir(parents=True,mode=0o755)
    (fixture/'run/tests').mkdir(mode=0o700)
    environment=os.environ.copy()
    environment.update({
        'TL_TEST_SSHD':str(daemon), 'TL_TEST_RUNTIME':'/run/tests',
        'TL_TEST_WITNESSCTL':str(binary_dir/'witnessctl'),
        'TL_TEST_EXPORTER':str(binary_dir/'witness-export'),
        'TL_TEST_GATE':str(binary_dir/'witness-ssh-gate'),
    })
    command=['/usr/bin/unshare','--mount','--propagation','private','/bin/sh','-c',
        'mount --bind "$1" /etc/passwd && mount --bind "$2" /run && exec "$3" --ignored --exact real_openssh_recovery_and_authorization --nocapture',
        'loopback-witness-test',str(fixture/'passwd'),str(fixture/'run'),str(test)]
    child=subprocess.Popen(command,env=environment,start_new_session=True)
    try:
        result=child.wait(timeout=120)
    except BaseException:
        os.killpg(child.pid,signal.SIGKILL)
        child.wait()
        raise
    if result:
        raise SystemExit(result)
