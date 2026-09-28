"""Reset the P4 into normal boot and print its console: monitor.py [port] [secs] [send-after-secs text]"""
import serial, sys, time
port = sys.argv[1] if len(sys.argv) > 1 else "/dev/ttyACM0"
secs = float(sys.argv[2]) if len(sys.argv) > 2 else 15
send_at = float(sys.argv[3]) if len(sys.argv) > 4 else None
text = sys.argv[4] if len(sys.argv) > 4 else ""
s = serial.Serial(port, 115200, timeout=0.2)
s.dtr = False; s.rts = True; time.sleep(0.1); s.rts = False
start = time.time()
while time.time() - start < secs:
    if send_at is not None and time.time() - start >= send_at:
        s.write(text.encode() + b"\n"); send_at = None
        print(f"\n>>> sent {text!r}", flush=True)
    sys.stdout.write(s.read(4096).decode(errors="replace")); sys.stdout.flush()
