#!/usr/bin/env python3
# sizes.py: spaced single sends so frames are separable in the capture. Mac side drives both directions (B via ssh). Writes event epoch times (Mac clock) and the Mac<->droplet clock offset.
import json,subprocess,sys,time
AN,BIN,AA,BA,SSH=sys.argv[1:6]
def now(): return time.time()
def ssh(c): return subprocess.run([SSH,c],capture_output=True,text=True).stdout
offs=[]
for _ in range(5):
    t1=now(); r=float(ssh("date +%s.%N")); t2=now(); offs.append(r-(t1+t2)/2)
off=sorted(offs)[2]; ev=[]
for i,body in enumerate(["s","s","s","tiny synthetic body"]):
    t=now(); json.loads(subprocess.run([AN,"--json","--data-dir","a","send",BA,body],capture_output=True,text=True).stdout); ev.append(("A_send",t,body)); time.sleep(7)
    t=now(); subprocess.run([SSH,f"{BIN} --json --data-dir /root/b send {AA} '{body}'"],capture_output=True,text=True); ev.append(("B_send",t,body)); time.sleep(7)
print(json.dumps({"droplet_minus_mac_clock_s":off,"events":ev}))
