"""P4 console. monitor.py [port] [secs] [send-at-secs text] [--no-reset]

Default resets the P4 into a normal boot first; --no-reset attaches to a
running board. secs <= 0 runs forever."""
import serial, sys, time
args = [a for a in sys.argv[1:] if a != "--no-reset"]
reset = "--no-reset" not in sys.argv
port = args[0] if args else "/dev/ttyACM0"
secs = float(args[1]) if len(args) > 1 else 15
send_at = float(args[2]) if len(args) > 3 else None
text = args[3] if len(args) > 3 else ""
s = serial.Serial(port, 115200, timeout=0.2, dsrdtr=False, rtscts=False)
if reset:
    s.dtr = False; s.rts = True; time.sleep(0.1); s.rts = False
start = time.time()
while secs <= 0 or time.time() - start < secs:
    if send_at is not None and time.time() - start >= send_at:
        s.write(text.encode() + b"\n"); send_at = None
        print(f"\n>>> sent {text!r}", flush=True)
    sys.stdout.write(s.read(4096).decode(errors="replace")); sys.stdout.flush()
