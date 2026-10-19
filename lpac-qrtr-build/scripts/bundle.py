#!/usr/bin/env python3
import hashlib, json, os, re, shutil, subprocess
from pathlib import Path
R = Path(__file__).resolve().parents[1]
bundle = R / 'out' / 'bundle'
bundle.mkdir(exist_ok=True)
shutil.copytree(R / 'out/stage/executables', bundle, dirs_exist_ok=True)
# Do not bundle fallback or interactive stdio APDU transports.
for p in (bundle / 'driver').glob('*stdio*'):
    p.unlink()
readelf = os.environ.get('READELF') or next(
    (p for p in (shutil.which('aarch64-linux-musl-readelf'), shutil.which('llvm-readelf'),
                 '/opt/homebrew/opt/llvm@21/bin/llvm-readelf', shutil.which('readelf')) if p and os.path.exists(p)), None)
if not readelf:
    raise SystemExit('readelf not found: set READELF (aarch64-linux-musl-readelf or llvm-readelf)')
def elf(p):
    return p.is_file() and p.open('rb').read(4) == b'\x7fELF'
def needed(p):
    s = subprocess.check_output([readelf, '-d', str(p)], text=True)
    return re.findall(r'\(NEEDED\).*?\[(.*?)\]', s)
pending = [p for p in bundle.rglob('*') if elf(p)]
manifest = []
seen = set()
while pending:
    p = pending.pop()
    if p.name in seen: continue
    seen.add(p.name)
    deps = needed(p)
    manifest.append({'path': str(p.relative_to(bundle)), 'needed': deps})
    for name in deps:
        dest = bundle / 'lib' / name
        if not dest.exists():
            candidates = [R/'sysroot/lib'/name, R/'sysroot/usr/lib'/name]
            src = next((x for x in candidates if x.exists()), None)
            if src is None: raise RuntimeError(f'Missing dependency {name} for {p}')
            shutil.copy2(src.resolve(), dest)
        pending.append(dest)
# Place loader beside lpac so /proc/self/exe still locates its driver directory.
shutil.copy2(R/'sysroot/lib/ld-musl-aarch64.so.1', bundle/'ld-musl-aarch64.so.1')
(bundle/'ld-musl-aarch64.so.1').chmod(0o755)
(R/'evidence/elf-dependencies.json').write_text(json.dumps(manifest, indent=2)+'\n')
shutil.copy2(R/'out/bounded', bundle/'bounded')
shutil.copy2(R/'scripts/smoke', bundle/'smoke')
(bundle/'smoke').chmod(0o755)
(bundle/'no-modules').mkdir(exist_ok=True)
# Trusted roots for the operators' SM-DP+ TLS certificates (passed to lpac as LPAC_HTTP_CA_FILE).
roots = sorted((R / 'certs').glob('*.pem'))
if not roots: raise SystemExit('certs/*.pem missing: lpac could not verify any SM-DP+ server')
(bundle / 'gsma-ci.pem').write_text(''.join(x.read_text() for x in roots))
# Build provenance for zte-agent's /api/esim/chip: no host or user names.
import datetime
lpac_src = sorted((R / 'sources').glob('lpac-*'))
digest = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
info = {
    'lpac_commit': lpac_src[-1].name.removeprefix('lpac-') if lpac_src else 'unknown',
    'patch_sha256': digest(R / 'patches/0001-isolated-qrtr-hardening.patch'),
    'alpine_pins_sha256': digest(R / 'evidence/alpine-packages.json'),
    'ca_sha256': digest(bundle / 'gsma-ci.pem'),
    'built_at': datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
}
(bundle / 'BUILDINFO').write_text(''.join(f'{k}={v}\n' for k, v in info.items()))
checks = []
for p in sorted(bundle.rglob('*')):
    if p.is_file() and p.name != 'SHA256SUMS': checks.append(f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(bundle)}')
(bundle/'SHA256SUMS').write_text('\n'.join(checks)+'\n')
print(f'Bundled {len(manifest)} ELF entries; dependency closure resolved locally.')
