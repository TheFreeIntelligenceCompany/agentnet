#!/usr/bin/env bash
# Run ON the droplet. $1 = Mac IP. Prints, for every spaced single send in sizes-events.json, the payload-bearing packets (dir, tcp payload bytes) in [t-0.5, t+4] s of droplet time, excluding the 4 flows other than the main one is NOT done: all flows shown.
MY=$1
python3 - "$MY" <<'PY'
import json,subprocess,sys,re
MY=sys.argv[1]; d=json.load(open('/root/sizes-events.json')); off=d["droplet_minus_mac_clock_s"]
out=subprocess.run(["tcpdump","-nn","-tt","-r","/root/pub.pcap","tcp"],capture_output=True,text=True).stdout.splitlines()
pk=[]
for l in out:
    m=re.match(r"(\d+\.\d+) IP (\S+)\.(\d+) > (\S+)\.(\d+): .*length (\d+)",l)
    if not m: continue
    t=float(m.group(1)); n=int(m.group(6))
    if n==0: continue
    if m.group(2)==MY and m.group(5)=="60000": pk.append((t,"A->R",n,m.group(3)))
    elif m.group(4)==MY and m.group(3)=="60000": pk.append((t,"R->A",n,m.group(5)))
for k,(name,t,body) in enumerate(d["events"]):
    T=t+off
    print(f"== event {k}: {name} body={body!r} at droplet t={T:.2f}")
    print("   "+" ".join(f"{dir}:{n}@{x-T:+.2f}" for x,dir,n,sp in pk if T-0.5<=x<=T+4.0))
PY
