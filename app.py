import socket
import threading

KISS_FEND = 0xC0
KISS_DATA = 0x00

# Conference state
conferences = {0: set()}  # Default conf 0
user_channels = {}
user_sockets = {}

def ax25_decode(frame):
    """Decode an AX.25 UI-frame (no CRC)"""
    def decode_callsign(raw):
        call = ''.join([chr((b >> 1) & 0x7F) for b in raw[:6]]).strip()
        ssid = (raw[6] >> 1) & 0x0F
        return f"{call}-{ssid}" if ssid else call

    dest = decode_callsign(frame[0:7])
    source = decode_callsign(frame[7:14])
    control = frame[14]
    pid = frame[15]
    payload = frame[16:]

    return {
        'from': source,
        'to': dest,
        'payload': payload.decode(errors='ignore')
    }

def kiss_unframe(data):
    frames = []
    frame = bytearray()
    in_frame = False

    for byte in data:
        if byte == KISS_FEND:
            if in_frame and frame:
                if frame[0] == KISS_DATA:
                    frames.append(bytes(frame[1:]))  # Skip port byte
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
                break
            buffer.extend(data)
            frames = kiss_unframe(buffer)
            for frame in frames:
                decoded = ax25_decode(frame)
                from_call = decoded['from']
                message = decoded['payload'].strip()
                print(f"<{from_call}> {message}")
                handle_convers_message(from_call, message, sock)
            buffer.clear()
        except Exception as e:
            print("Error:", e)
            break

def handle_convers_message(callsign, message, sock):
    if callsign not in user_channels:
        user_channels[callsign] = 0  # Default conf 0
        conferences[0].add(callsign)
        user_sockets[callsign] = sock

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
        # Echo to terminal (for now)
        print(f"[to {callsign}] {message}")

def broadcast(conf, message, exclude=None):
    for user in conferences.get(conf, []):
        if user != exclude:
            send_to_user(user, message)

def start_server(host='127.0.0.1', port=8001):
    print(f"Connecting to Direwolf KISS TCP on {host}:{port}...")
    sock = socket.create_connection((host, port))
    print("Connected.")
    threading.Thread(target=handle_client, args=(sock,), daemon=True).start()
    print("Listening for packets... Press Ctrl+C to stop.")
    while True:
        try:
            pass  # Keep main thread alive
        except KeyboardInterrupt:
            print("Shutting down.")
            break

if __name__ == '__main__':
    start_server()
