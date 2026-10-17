#!/usr/bin/env python3
import gzip, os, stat, re, subprocess
from pathlib import Path
R=Path(__file__).resolve().parents[1]
entries={}
def add(name,mode,data=b'',major=0,minor=0): entries[name]=(mode,data,major,minor)
def directory(name): add(name,stat.S_IFDIR|0o755)
def file(name,source):
    p=Path(source)
    if p.is_symlink(): add(name,stat.S_IFLNK|0o777,os.readlink(p).encode())
    else: add(name,stat.S_IFREG|(p.stat().st_mode&0o777),p.read_bytes())
for d in ['bin','sbin','dev','proc','sys','tmp','lib','bundle','tests','evidence','empty-gio','testlib']:
    directory(d)
file('bin/busybox',R/'sysroot/bin/busybox')
add('bin/sh',stat.S_IFLNK|0o777,b'busybox')
file('lib/ld-musl-aarch64.so.1',(R/'sysroot/lib/ld-musl-aarch64.so.1').resolve())
add('lib/libc.musl-aarch64.so.1',stat.S_IFLNK|0o777,b'ld-musl-aarch64.so.1')
add('dev/console',stat.S_IFCHR|0o600,major=5,minor=1)
file('bin/strace',R/'sysroot/usr/bin/strace')
pending=[R/'sysroot/usr/bin/strace'];seen=set()
while pending:
    p=pending.pop()
    for name in re.findall(r'\(NEEDED\).*?\[(.*?)\]',subprocess.check_output(['/opt/homebrew/opt/llvm@21/bin/llvm-readelf','-d',str(p)],text=True)):
        if name in seen:continue
        seen.add(name)
        src=next(x for x in [R/'sysroot/lib'/name,R/'sysroot/usr/lib'/name] if x.exists()).resolve()
        file('testlib/'+name,src);pending.append(src)
for top in ['out/bundle','out/tests']:
    name='bundle' if top.endswith('bundle') else 'tests'
    for p in sorted((R/top).rglob('*')):
        dest=f'{name}/{p.relative_to(R/top)}'
        if p.is_dir():directory(dest)
        elif p.is_file() or p.is_symlink():file(dest,p)
file('init',R/'vm/init.sh')
entries['init']=(stat.S_IFREG|0o755,entries['init'][1],0,0)
out=bytearray()
for idx,(name,(mode,data,major,minor)) in enumerate([*entries.items(),('TRAILER!!!',(0,b'',0,0))],1):
    rawname=name.encode()+b'\0'
    values=[idx,mode,0,0,1,0,len(data),0,0,major,minor,len(rawname),0]
    out.extend(b'070701'+''.join(f'{v:08x}' for v in values).encode())
    out.extend(rawname);out.extend(b'\0'*(-len(out)%4))
    out.extend(data);out.extend(b'\0'*(-len(out)%4))
(R/'vm/initramfs.cpio.gz').write_bytes(gzip.compress(out,mtime=0))
print(f'Initramfs: {len(entries)} entries, {len(out)} bytes uncompressed')
