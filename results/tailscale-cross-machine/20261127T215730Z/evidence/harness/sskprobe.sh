#!/bin/sh
# diagnose `ss -K` on this host: which invocations print RTNETLINK EINVAL, and does a real kill work?
echo "iproute2: $(ss -V 2>&1)  kernel: $(uname -r)"
echo "## A: filter that matches nothing"; out=$(ss -K state established "( sport = :60000 and dport = :0 )" 2>&1 >/dev/null); echo "exit=$? stderr=[$out]"
python3 -c '
import socket,time
l=socket.socket();l.bind(("127.0.0.1",45678));l.listen();c=socket.create_connection(("127.0.0.1",45678));a,_=l.accept();time.sleep(15)' &
sleep 1
echo "## B: real established pair on loopback, kill server-side socket (sport 45678)"
ss -tn state established "( sport = :45678 or dport = :45678 )"
out=$(ss -K state established "( sport = :45678 )" 2>&1 >/dev/null); echo "exit=$? stderr=[$out]"; sleep 1
echo "after:"; ss -tn state established "( sport = :45678 or dport = :45678 )"
wait
