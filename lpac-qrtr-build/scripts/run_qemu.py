#!/usr/bin/env python3
import os, subprocess, sys
from pathlib import Path
R=Path(__file__).resolve().parents[1]
q=next((R/'host-qemu').glob('qemu/*/bin/qemu-system-aarch64'))
env=os.environ.copy()
env['DYLD_LIBRARY_PATH']=':'.join(str(p) for p in list((R/'host-qemu').glob('*/*/lib'))+list(Path('/opt/homebrew/opt').glob('*/lib')))
command=[str(q),'-machine','virt,accel=tcg','-cpu','cortex-a72','-m','1024','-smp','2',
 '-display','none','-nodefaults','-serial','stdio','-monitor','none','-nic','none','-no-reboot',
 '-kernel',str(R/'vm/vmlinuz-5.15') if (R/'vm/vmlinuz-5.15').exists() else str(R/'sysroot/boot/vmlinuz-virt'),'-initrd',str(R/'vm/initramfs.cpio.gz'),
 '-append','console=ttyAMA0 rdinit=/init panic=-1 quiet']
log=R/'evidence'/(sys.argv[1] if len(sys.argv)>1 else 'qemu-tests.log')
with log.open('w') as out:
    try:p=subprocess.run(command,env=env,stdout=out,stderr=subprocess.STDOUT,timeout=240)
    except subprocess.TimeoutExpired:print('QEMU timed out');sys.exit(124)
text=log.read_text()
print(text[-12000:])
if p.returncode or 'OFF_DEVICE_TEST_SUITE_EXIT=0' not in text:sys.exit(1)
