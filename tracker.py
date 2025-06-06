# tracker.py
import socket
import threading
import json
import time
from datetime import datetime

HOST = '0.0.0.0'  # Listen on all available network interfaces
PORT = 8000
BUFFER_SIZE = 4096

# A thread-safe dictionary to store user information
# Format: { "username": {"ip": str, "port": int, "public_key": str, "last_seen": float} }
online_users = {}
users_lock = threading.Lock()

def log(message):
    """Prints a log message with a timestamp."""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print(f"[{timestamp}] {message}")

def cleanup_inactive_users():
    """Periodically checks for and removes inactive users."""
    while True:
        time.sleep(60)  # Check every 60 seconds
        with users_lock:
            current_time = time.time()
            inactive_users = [
                user for user, data in online_users.items()
                if current_time - data.get('last_seen', 0) > 120  # 2-minute timeout
            ]
            for user in inactive_users:
                del online_users[user]
                log(f"Removed inactive user: {user}")

def handle_client(conn, addr):
    """Handles a single client connection."""
    log(f"New connection from {addr}")
    try:
        while True:
            data = conn.recv(BUFFER_SIZE)
            if not data:
                break
            
            request = json.loads(data.decode('utf-8'))
            command = request.get("command")
            
            with users_lock:
                if command == "REGISTER":
                    username = request.get("username")
                    port = request.get("port")
                    public_key = request.get("public_key")
                    if username and port and public_key:
                        online_users[username] = {
                            "ip": addr[0],
                            "port": port,
                            "public_key": public_key,
                            "last_seen": time.time()
                        }
                        log(f"Registered user '{username}' from {addr[0]}:{port}")
                        conn.sendall(json.dumps({"status": "OK", "message": "Registered successfully"}).encode('utf-8'))
                    else:
                        conn.sendall(json.dumps({"status": "ERROR", "message": "Missing registration info"}).encode('utf-8'))

                elif command == "GET_USERS":
                    username = request.get("username")
                    if username in online_users:
                        online_users[username]['last_seen'] = time.time() # Update timestamp
                    
                    # Return all users except the one asking
                    users_to_send = {u: d for u, d in online_users.items() if u != username}
                    conn.sendall(json.dumps(users_to_send).encode('utf-8'))

                elif command == "DEREGISTER":
                    username = request.get("username")
                    if username in online_users:
                        del online_users[username]
                        log(f"Deregistered user: {username}")
                        conn.sendall(json.dumps({"status": "OK", "message": "Deregistered"}).encode('utf-8'))
                
                else:
                    conn.sendall(json.dumps({"status": "ERROR", "message": "Unknown command"}).encode('utf-8'))

    except (ConnectionResetError, json.JSONDecodeError, BrokenPipeError) as e:
        log(f"Connection error with {addr}: {e}")
    finally:
        # On disconnect, find and remove the user associated with this connection
        with users_lock:
            user_to_remove = None
            for username, data in online_users.items():
                if data['ip'] == addr[0]: # This is a simplification; multiple users could be behind one IP
                    # A more robust system would use a session ID
                    pass
            # For now, we rely on DEREGISTER and the inactivity cleanup
        conn.close()
        log(f"Connection closed with {addr}")


def main():
    """Main function to start the tracker server."""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen(10)
    log(f"Tracker server listening on {HOST}:{PORT}")

    # Start the cleanup thread
    cleanup_thread = threading.Thread(target=cleanup_inactive_users, daemon=True)
    cleanup_thread.start()

    while True:
        conn, addr = server_socket.accept()
        client_thread = threading.Thread(target=handle_client, args=(conn, addr))
        client_thread.start()

if __name__ == "__main__":
    main()