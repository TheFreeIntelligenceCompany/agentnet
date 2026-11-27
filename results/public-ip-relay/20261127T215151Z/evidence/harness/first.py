import json,subprocess,sys,time
b,d,r,t=sys.argv[1:5]
def an(*a): return json.loads(subprocess.run([b,"--json","--data-dir",d,*a],capture_output=True,text=True,check=True).stdout)
m=an("send",r,t);t0=time.time()
while True:
    s=an("status",m["message_id"])
    if s["state"]=="delivered": print(json.dumps({"message_id":m["message_id"],"latency_ms":s["delivered_at"]-s["created_at"],"status":s})); break
    if time.time()-t0>120: print(json.dumps({"timeout":s})); break
    time.sleep(0.1)
