#!/usr/bin/env python3
"""Workspace-only Homebrew bottle extraction, not a Homebrew installation."""
import hashlib, json, tarfile, urllib.request
from pathlib import Path
R=Path(__file__).resolve().parents[1]
records=[]
def formula(name):
    p=R/'downloads'/f'{name}-formula.json'
    if not p.exists():p.write_bytes(urllib.request.urlopen(f'https://formulae.brew.sh/api/formula/{name}.json').read())
    return json.loads(p.read_bytes())
pending=['qemu'];seen=set()
while pending:
    name=pending.pop()
    if name in seen:continue
    seen.add(name)
    f=formula(name)
    for dep in f['dependencies']:
        if not (Path('/opt/homebrew/opt')/dep).exists():pending.append(dep)
    b=f['bottle']['stable']['files']['arm64_tahoe']
    dest=R/'downloads'/f"{name}-{f['versions']['stable']}.bottle.tar.gz"
    if not dest.exists():
        token=json.load(urllib.request.urlopen(f'https://ghcr.io/token?service=ghcr.io&scope=repository:homebrew/core/{name}:pull'))['token']
        req=urllib.request.Request(b['url'],headers={'Authorization':'Bearer '+token})
        with urllib.request.urlopen(req,timeout=120) as response:dest.write_bytes(response.read())
    digest=hashlib.sha256(dest.read_bytes()).hexdigest()
    if digest!=b['sha256']:raise RuntimeError('Bottle checksum mismatch: '+name)
    with tarfile.open(dest) as t:t.extractall(R/'host-qemu',filter='data')
    records.append({'name':name,'version':f['versions']['stable'],'url':b['url'],'sha256':digest})
(R/'evidence/qemu-bottles.json').write_text(json.dumps(records,indent=2)+'\n')
print('Extracted verified bottles:', ', '.join(x['name'] for x in records))
