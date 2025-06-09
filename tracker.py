
import socket
import threading
import json
import time
import struct
from datetime import datetime

HOST = '0.0.0.0'
PORT = 8000

online_users = {}
users_lock = threading.Lock()

def log(message):
    """Logs a message to the console with a timestamp."""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print(f"[{timestamp}] [Tracker] {message}")

def send_framed_message(sock, message_dict):
    """Sends a JSON message prefixed with its length."""
    try:
        message_json = json.dumps(message_dict).encode('utf-8')
        header = struct.pack('!I', len(message_json))
        sock.sendall(header + message_json)
    except Exception as e:
        log(f"Error sending framed message: {e}")

def receive_framed_message(sock):
    """Receives a JSON message prefixed with its length."""
    try:
        header_data = sock.recv(4)
        if not header_data: return None
        message_length = struct.unpack('!I', header_data)[0]
        
        full_message_data = b''
        while len(full_message_data) < message_length:
            chunk = sock.recv(message_length - len(full_message_data))
            if not chunk: return None
            full_message_data += chunk
            
        return json.loads(full_message_data.decode('utf-8'))
    except (struct.error, json.JSONDecodeError, ConnectionResetError) as e:
        log(f"Error receiving framed message: {e}")
        return None

def cleanup_inactive_users():
    """Periodically removes users who haven't polled in a while."""
    while True:
        time.sleep(60)
        with users_lock:
            current_time = time.time()
            # Users are considered inactive after 120 seconds
            inactive_users = [
                user for user, data in online_users.items()
                if current_time - data.get('last_seen', 0) > 120
            ]
            for user in inactive_users:
                del online_users[user]
                log(f"Removed inactive user due to timeout: {user}")

def handle_client(conn, addr):
    """Handles a single client request."""
    log(f"Accepted new TCP connection from {addr}")
    try:
        request = receive_framed_message(conn)
        if not request:
            log(f"Connection from {addr} sent invalid or no data. Closing.")
            return

        command = request.get("command")
        log(f"Received command '{command}' from {addr}")
        
        with users_lock:
            if command == "REGISTER":
                username = request.get("username")
                if username in online_users:
                    log(f"Registration failed for '{username}': username already taken.")
                    send_framed_message(conn, {"status": "ERROR", "message": "Username already taken."})
                    return
                port = request.get("port")
                public_key = request.get("public_key")
                if username and port and public_key:
                    online_users[username] = {
                        "ip": addr[0], "port": port,
                        "public_key": public_key, "last_seen": time.time()
                    }
                    log(f"Registered user '{username}' at {addr[0]}:{port}")
                    send_framed_message(conn, {"status": "OK", "message": "Registered successfully"})
                else:
                    log(f"Registration failed for '{username}': missing information.")
                    send_framed_message(conn, {"status": "ERROR", "message": "Missing registration info"})

            elif command == "GET_USERS":
                username = request.get("username")
                # Update the user's last_seen timestamp to keep them "alive"
                if username in online_users:
                    online_users[username]['last_seen'] = time.time()
                
                # Return all other users
                users_to_send = {u: d for u, d in online_users.items() if u != username}
                log(f"Sent user list to '{username}'. Found {len(users_to_send)} other users.")
                send_framed_message(conn, users_to_send)

            elif command == "DEREGISTER":
                username = request.get("username")
                if username in online_users:
                    del online_users[username]
                    log(f"Deregistered user: {username}")
                    send_framed_message(conn, {"status": "OK", "message": "Deregistered"})
                else:
                    log(f"Deregister command for non-existent user: {username}")
            
            else:
                log(f"Received unknown command '{command}' from {addr}")
                send_framed_message(conn, {"status": "ERROR", "message": "Unknown command"})

    except Exception as e:
        log(f"An unexpected error occurred with {addr}: {e}")
    finally:
        conn.close()
        log(f"TCP connection closed with {addr}")

def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen(10)
    log(f"Tracker server listening on {HOST}:{PORT} using TCP")

    cleanup_thread = threading.Thread(target=cleanup_inactive_users, daemon=True)
    cleanup_thread.start()
    log("Started inactive user cleanup thread.")

    while True:
        conn, addr = server_socket.accept()
        client_thread = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
        client_thread.start()

if __name__ == "__main__":
    main()