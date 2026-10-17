#!/usr/bin/env python3
"""Extract pinned Alpine packages locally; never run APK scripts or install on host."""
import concurrent.futures, gzip, hashlib, io, json, os, tarfile, urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
packages, providers = {}, {}
for repo in ('main', 'community'):
    for block in (ROOT / 'downloads' / f'alpine-{repo}-APKINDEX').read_text().split('\n\n'):
        d = dict(line.split(':', 1) for line in block.splitlines() if ':' in line)
        if 'P' not in d:
            continue
        d['repo'] = repo
        packages[d['P']] = d
        for cap in d.get('p', '').split():
            providers[cap.split('=')[0]] = d['P']

seeds = '''musl-dev linux-headers libqmi-dev libqrtr-glib-dev glib-dev libmbim-dev curl-dev
libffi-dev pcre2-dev zlib-dev openssl-dev util-linux-dev
gettext-dev zstd-dev brotli-dev nghttp2-dev c-ares-dev libpsl-dev
libidn2-dev libunistring-dev busybox linux-virt libgcc libstdc++ strace'''.split()
selected = set(seeds)
# Only library and pkg-config dependencies: package maintainer scripts, daemons,
# locale catalogs and host build utilities are not executed or needed here.
pending = list(seeds)
while pending:
    name = pending.pop()
    for dep in packages[name].get('D', '').split():
        key = dep.split('=')[0].split('>')[0].split('<')[0]
        target = providers.get(key) if key.startswith(('so:', 'pc:')) else None
        if not target and key in packages and (key.startswith('lib') or key in ('musl', 'glib', 'zlib', 'pcre2', 'gettext-libs', 'openssl')):
            target = key
        if target and target not in selected:
            selected.add(target)
            pending.append(target)

def fetch(name):
    d = packages[name]
    fn = f"{name}-{d['V']}.apk"
    url = f"https://dl-cdn.alpinelinux.org/alpine/v3.22/{d['repo']}/aarch64/{fn}"
    dest = ROOT / 'downloads' / fn
    if not dest.exists():
        with urllib.request.urlopen(url, timeout=90) as r:
            dest.write_bytes(r.read())
    data = dest.read_bytes()
    return {'name': name, 'version': d['V'], 'url': url, 'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data), 'depends': d.get('D', ''), 'file': fn}

with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
    manifest = list(pool.map(fetch, sorted(selected)))
(ROOT / 'evidence' / 'alpine-packages.json').write_text(json.dumps(manifest, indent=2) + '\n')
sysroot = ROOT / 'sysroot'
for d in manifest:
    raw = gzip.decompress((ROOT / 'downloads' / d['file']).read_bytes())
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:', ignore_zeros=True) as tar:
        for m in tar:
            # APK control metadata and scripts are intentionally omitted.
            if m.name.startswith('.') or m.name.startswith('/') or '..' in Path(m.name).parts:
                continue
            dest = sysroot / m.name
            dest.parent.mkdir(parents=True, exist_ok=True)
            if m.isdir():
                dest.mkdir(exist_ok=True)
            elif m.issym():
                # Relativize absolute links so no sysroot link resolves on host.
                link = m.linkname
                if link.startswith('/'):
                    link = os.path.relpath(sysroot / link.lstrip('/'), dest.parent)
                if dest.is_symlink() or dest.exists():
                    dest.unlink()
                dest.symlink_to(link)
            elif m.isfile():
                if dest.is_symlink():
                    dest.unlink()
                dest.write_bytes(tar.extractfile(m).read())
                dest.chmod(m.mode & 0o777)
            elif m.islnk():
                src = sysroot / m.linkname
                if src.exists():
                    dest.write_bytes(src.read_bytes())
                    dest.chmod(m.mode & 0o777)
print(f'Extracted {len(manifest)} packages to {sysroot}; no scripts executed.')
