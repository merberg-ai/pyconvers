import socket
import threading

KISS_FEND = 0xC0
KISS_DATA = 0x00

# Conference state
conferences = {0: set()}  # Default conf 0
user_channels = {}
user_sockets = {}

def ax25_decode(frame):
    """Decode AX.25 frame and return full metadata."""
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

    # Determine control type
    if control == 0x03:
        ctrl_type = "UI"
    elif (control & 0x01) == 0x00:
        ctrl_type = "I"
    elif (control & 0x03) == 0x01:
        s_code = control & 0x0F
        if s_code == 0x01:
            ctrl_type = "RR"
        elif s_code == 0x05:
            ctrl_type = "REJ"
        elif s_code == 0x09:
            ctrl_type = "RNR"
        elif s_code == 0x0D:
            ctrl_type = "SREJ"
        else:
            ctrl_type = f"S(0x{control:02X})"
    else:
        ctrl_type = f"UNKNOWN(0x{control:02X})"

    return {
        'from': source,
        'to': dest,
        'type': ctrl_type,
        'pid': pid,
        'payload': payload.decode(errors='ignore').replace('\r', '').replace('\x0d', '').strip(),
        'raw': frame
    }

def kiss_unframe(data):
    """Unwrap KISS frames from raw TCP data stream."""
    frames = []
    frame = bytearray()
    in_frame = False

    for byte in data:
        if byte == KISS_FEND:
            if in_frame and frame:
                if frame[0] == KISS_DATA:
                    frames.append(bytes(frame[1:]))  # strip port byte
                frame = bytearray()
            in_frame = True
        else:
            if in_frame:
                frame.append(byte)

    return frames

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

                    # Print like axlisten
                    if payload:
                        print(f"{from_call:9} > {to_call:9} [{ctrl_type:>3}] : {payload}")
                    else:
                        print(f"{from_call:9} > {to_call:9} [{ctrl_type:>3}]")

                    # Handle convers-style commands
                    if ctrl_type == "UI" and payload.startswith("/"):
                        handle_convers_message(from_call, payload.strip(), sock)

                except Exception as e:
                    print(f"[Frame Decode Error] {e}")
                    print(f"[Raw] {frame.hex()}")

            buffer.clear()
        except Exception as e:
            print(f"[Socket Error] {e}")
            break

def handle_convers_message(callsign, message, sock):
    if callsign not in user_channels:
        user_channels[callsign] = 0
        conferences[0].add(callsign)
        user_sockets[callsign] = sock
        print(f"[+] {callsign} joined conf 0")

    conf = user_channels[callsign]

    if message.startswith("/join "):
        try:
            new_conf = int(message.split()[1])
            conferences.setdefault(new_conf, set()).add(callsign)
            conferences[conf].discard(callsign)
            user_channels[callsign] = new_conf
            send_to_user(callsign, f"You joined conference {new_conf}")
        except ValueError:
            send_to_user(callsign, "Usage: /join <number>")

    elif message.startswith("/who"):
        members = ', '.join(sorted(conferences.get(conf, [])))
        send_to_user(callsign, f"Users in conf {conf}: {members}")

    else:
        broadcast(conf, f"<{callsign}> {message}", exclude=callsign)

def send_to_user(callsign, message):
    sock = user_sockets.get(callsign)
    if sock:
        print(f"[to {callsign}] {message}")
        # TODO: implement sending back via AX.25 if desired

def broadcast(conf, message, exclude=None):
    for user in conferences.get(conf, []):
        if user != exclude:
            send_to_user(user, message)

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
