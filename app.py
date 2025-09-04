import socket
import threading
import datetime

MY_CALLSIGN = "N0CALL-9"  # <-- Change this!
KISS_FEND = 0xC0
KISS_DATA = 0x00

# State
bbs_messages = []
user_sessions = {}
LOGFILE = open("ax25_log.txt", "a")

def ax25_decode(frame):
    if len(frame) < 15:
        raise ValueError(f"Frame too short: {len(frame)} bytes")

    def decode_callsign(raw):
        call = ''.join([chr((b >> 1) & 0x7F) for b in raw[:6]]).strip()
        ssid = (raw[6] >> 1) & 0x0F
        return f"{call}-{ssid}" if ssid else call

    dest = decode_callsign(frame[0:7])
    source = decode_callsign(frame[7:14])
    control = frame[14]
    pid = frame[15] if len(frame) > 15 else None
    payload = frame[16:] if len(frame) > 16 else b''

    if control == 0x03:
        ctrl_type = "UI"
    elif (control & 0x01) == 0x00:
        ctrl_type = "I"
    elif (control & 0x03) == 0x01:
        s_code = control & 0x0F
        ctrl_type = {0x01: "RR", 0x05: "REJ", 0x09: "RNR", 0x0D: "SREJ"}.get(s_code, f"S(0x{control:02X})")
    else:
        ctrl_type = f"UNK(0x{control:02X})"

    return {
        'from': source,
        'to': dest,
        'type': ctrl_type,
        'pid': pid,
        'payload': payload.decode(errors='ignore').replace('\r', '').strip(),
        'raw': frame
    }

def kiss_unframe(data):
    frames = []
    frame = bytearray()
    in_frame = False

    for byte in data:
        if byte == KISS_FEND:
            if in_frame and frame:
                if frame[0] == KISS_DATA:
                    frames.append(bytes(frame[1:]))
                frame = bytearray()
            in_frame = True
        else:
            if in_frame:
                frame.append(byte)

    return frames

def log_packet(from_call, to_call, ctrl_type, payload):
    direction = "TX" if from_call == MY_CALLSIGN else "RX"
    timestamp = datetime.datetime.now().isoformat()
    logline = f"[{direction}] {from_call:9} > {to_call:9} [{ctrl_type:>3}] : {payload}"
    print(logline)
    LOGFILE.write(f"{timestamp} {logline}\n")
    LOGFILE.flush()

def handle_client(sock):
    buffer = bytearray()
    while True:
        try:
            data = sock.recv(1024)
            if not data:
                print("Connection closed.")
                break

            buffer.extend(data)
            frames = kiss_unframe(buffer)

            for frame in frames:
                try:
                    decoded = ax25_decode(frame)
                    from_call = decoded['from']
                    to_call = decoded['to']
                    ctrl_type = decoded['type']
                    payload = decoded['payload']

                    log_packet(from_call, to_call, ctrl_type, payload)

                    if ctrl_type == "UI" and payload:
                        handle_bbs_input(from_call, payload)
                except Exception as e:
                    print(f"[Frame Decode Error] {e}")
                    print(f"[Raw] {frame.hex()}")

            buffer.clear()
        except Exception as e:
            print(f"[Socket Error] {e}")
            break

def handle_bbs_input(callsign, payload):
    session = user_sessions.setdefault(callsign, {'state': 'idle', 'msg_lines': []})

    if session['state'] == 'writing':
        if payload == ".":
            message = '\n'.join(session['msg_lines'])
            bbs_messages.append((callsign, message, datetime.datetime.now()))
            send_line(callsign, "Message saved.\n")
            session['msg_lines'].clear()
            session['state'] = 'idle'
        else:
            session['msg_lines'].append(payload)
        return

    cmd = payload.strip().upper()

    if cmd == '?':
        send_line(callsign, "Commands: I = Info, L = List, R # = Read, S = Send, Q = Quit, ? = Help")
    elif cmd == 'I':
        send_line(callsign, f"Welcome {callsign}. This is RetroPy BBS 1.0")
    elif cmd == 'L':
        if not bbs_messages:
            send_line(callsign, "No messages.")
        else:
            for i, (sender, _, ts) in enumerate(bbs_messages):
                send_line(callsign, f"{i+1:03d}) {sender} @ {ts.strftime('%H:%M %b %d')}")
    elif cmd.startswith('R '):
        try:
            index = int(cmd.split()[1]) - 1
            if 0 <= index < len(bbs_messages):
                sender, msg, ts = bbs_messages[index]
                send_line(callsign, f"From: {sender}\nDate: {ts}\n\n{msg}")
            else:
                send_line(callsign, "Invalid message number.")
        except:
            send_line(callsign, "Usage: R <message number>")
    elif cmd == 'S':
        send_line(callsign, "Enter your message. End with a single dot (.) on its own line.")
        session['state'] = 'writing'
        session['msg_lines'] = []
    elif cmd == 'Q':
        send_line(callsign, "Bye.\n")
        del user_sessions[callsign]
    else:
        send_line(callsign, f"Unknown command: {payload}")

def send_line(callsign, message):
    print(f"[to {callsign}] {message.strip()}")  # Placeholder — not sending back over AX.25 (yet)

def start_server(host='127.0.0.1', port=8001):
    print(f"Connecting to Direwolf on {host}:{port}...")
    sock = socket.create_connection((host, port))
    print("Connected to Direwolf via KISS TCP.")
    threading.Thread(target=handle_client, args=(sock,), daemon=True).start()
    print("Listening for AX.25 packets... (Ctrl+C to stop)")
    try:
        while True:
            pass
    except KeyboardInterrupt:
        print("Shutting down.")

if __name__ == '__main__':
    start_server()
