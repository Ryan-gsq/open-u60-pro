#!/usr/bin/env python3
"""Analyze a /tmp/measure-<label> capture fetched from the router into a local dir."""
import os, re, sys, collections
d = sys.argv[1]
def rd(p):
    with open(os.path.join(d, p)) as f: return f.read()
def stat_fields(s):  # handle "(comm)" with spaces
    rp = s.rfind(')'); return s[rp+2:].split()
def ptime(p):
    f = stat_fields(rd(p))  # fields from state (index 0 == field 3)
    return dict(utime=int(f[11]), stime=int(f[12]), cutime=int(f[13]), cstime=int(f[14]), threads=int(f[17]))
t0, t1 = ptime('t0/stat'), ptime('t1/stat')
up0, up1 = float(rd('t0/uptime').split()[0]), float(rd('t1/uptime').split()[0])
secs = up1 - up0
# CLK_TCK estimate from thread schedstat vs ticks
def tasks(tag):
    st, ss, wc, sc = {}, {}, {}, {}
    for line in rd(f'{tag}/task_stat').splitlines():
        tid, rest = line.split(' ', 1); f = stat_fields(rest)
        if len(f) < 20: continue
        st[tid] = int(f[11]) + int(f[12])
    for line in rd(f'{tag}/task_schedstat').splitlines():
        p = line.split()
        if len(p) < 2: continue
        ss[p[0]] = int(p[1])
    for line in rd(f'{tag}/task_wchan').splitlines():
        p = line.split(' ', 1); wc[p[0]] = p[1] if len(p) > 1 else ''
    cur = None
    for line in rd(f'{tag}/task_sched').splitlines():
        if line.startswith('== '): cur = line[3:].strip(); sc[cur] = {}
        elif cur and ':' in line:
            k, v = line.split(':', 1); sc[cur][k.strip()] = v.strip()
    return st, ss, wc, sc
st0, ss0, wc0, sc0 = tasks('t0'); st1, ss1, wc1, sc1 = tasks('t1')
tick_sum = sum(st1.values()); ns_sum = sum(ss1.values())
clk = round(tick_sum / (ns_sum / 1e9)) if ns_sum else 100
print(f"capture {d}: {secs:.1f}s  (CLK_TCK≈{clk}, threads {t0['threads']}->{t1['threads']})")
cpu_ms = ((t1['utime']+t1['stime']) - (t0['utime']+t0['stime'])) * 1000 / clk
kid_ms = ((t1['cutime']+t1['cstime']) - (t0['cutime']+t0['cstime'])) * 1000 / clk
print(f"agent own CPU: {cpu_ms:.0f} ms  ({cpu_ms/10/secs:.3f}% of one core)")
print(f"reaped children CPU: {kid_ms:.0f} ms ({kid_ms/10/secs:.3f}%)")
procs0 = int(re.search(r'processes (\d+)', rd('t0/procstat')).group(1)); procs1 = int(re.search(r'processes (\d+)', rd('t1/procstat')).group(1))
ctxt0 = int(re.search(r'ctxt (\d+)', rd('t0/procstat')).group(1)); ctxt1 = int(re.search(r'ctxt (\d+)', rd('t1/procstat')).group(1))
print(f"system-wide forks: {procs1-procs0} ({(procs1-procs0)/secs:.2f}/s); context switches {ctxt1-ctxt0} ({(ctxt1-ctxt0)/secs:.0f}/s)")
print("\nper-thread (delta over capture):")
print(f"{'tid':>6} {'wchan':<28} {'cpu_ms':>7} {'switches':>9} {'wake/s':>7}")
rows = []
for tid in ss1:
    ns = ss1[tid] - ss0.get(tid, 0)
    sw = int(sc1[tid].get('nr_switches', 0)) - int(sc0.get(tid, {}).get('nr_switches', 0))
    rows.append((sw, tid, wc1.get(tid, ''), ns/1e6))
for sw, tid, w, ms in sorted(rows, key=lambda r: (-r[0], -r[3])):
    if sw or ms >= 0.5: print(f"{tid:>6} {w[:28]:<28} {ms:7.1f} {sw:9d} {sw/secs:7.2f}")
tot_sw = sum(r[0] for r in rows); print(f"total agent thread switches: {tot_sw} = {tot_sw/secs:.1f}/s")
# trace: forks by agent threads and the exec'd commands of those children
if os.path.exists(os.path.join(d, 'trace')):
    forks, execs, names = [], {}, {}
    agent = rd('pid').strip().split('=')[1]
    for line in rd('trace').splitlines():
        m = re.search(r'sched_process_fork: comm=(\S+) pid=(\d+) child_comm=\S+ child_pid=(\d+)', line)
        if m:
            # record-tgid captures carry "(  TGID)"; older captures were filtered on comm already.
            tg = re.search(r'\(\s*(\d+|-+)\)\s+\[\d+\]', line)
            if tg and tg.group(1) != agent: continue
            names[m.group(2)] = m.group(1); forks.append((m.group(2), m.group(3))); continue
        m = re.search(r'sched_process_exec: filename=(\S+) pid=(\d+)', line)
        if m: execs.setdefault(m.group(2), []).append(m.group(1))
    print(f"\nagent forks: {len(forks)} ({len(forks)/secs*60:.1f}/min)")
    cmds = collections.Counter()
    by_tid = collections.Counter()
    for ptid, cpid in forks:
        ex = execs.get(cpid, ['<no exec: fork only / sh builtin>'])
        cmds[' -> '.join(e if e.startswith('<') else os.path.basename(e) for e in ex)] += 1; by_tid[ptid] += 1
    for c, n in cmds.most_common(): print(f"  {n:5d}  {c}")
    print("forks by thread:", {f"{t} {names.get(t, '')}": n for t, n in by_tid.most_common()})
tcp0 = rd('t0/tcp9090').splitlines(); tcp1 = rd('t1/tcp9090').splitlines()
est = lambda L: sum(1 for l in L if l.split()[2] == '01')
print(f"\n:9090 sockets t0={len(tcp0)} (established {est(tcp0)}), t1={len(tcp1)} (established {est(tcp1)})")
