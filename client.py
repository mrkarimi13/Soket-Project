
import customtkinter as ctk
import socket
import threading
import json
import time
import random
import hashlib
import base64
import os
import math
import struct
import queue
from tkinter import filedialog, messagebox
from datetime import datetime

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.fernet import Fernet

try:
    from voice_call import VoiceCall
    VOICE_CALL_ENABLED = True
except ImportError:
    VOICE_CALL_ENABLED = False
    print("Warning: voice_call.py not found. Voice call feature will be disabled.")

# --- Constants ---
LOG_FILE = "report.log" 
LOG_LOCK = threading.Lock()
FILE_CHUNK_SIZE = 4096 * 2

# --- Utility Functions ---
def log_event(message, level="INFO", log_file_override=None):
    """
    Writes a structured message to the log file and prints to console.
    Allows overriding the log file path for testing purposes.
    """
    global LOG_FILE
    output_file = log_file_override if log_file_override is not None else LOG_FILE

    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_message = f"[{timestamp}] [{level}] {message}\n"
    print(log_message.strip())
    
    # Use the global lock to prevent race conditions
    with LOG_LOCK:
        with open(output_file, "a", encoding='utf-8') as f:
            f.write(log_message)

def generate_keys():
    log_event("Generating new RSA-2048 key pair.", level="CRYPTO")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key, private_key.public_key()

def serialize_public_key(public_key):
    return public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode('utf-8')

def deserialize_public_key(pem_data):
    return serialization.load_pem_public_key(pem_data.encode('utf-8'))

def format_filesize(size_bytes):
    if size_bytes == 0: return "0B"
    size_name = ("B", "KB", "MB", "GB", "TB")
    i = int(math.floor(math.log(size_bytes, 1024)))
    p = math.pow(1024, i)
    s = round(size_bytes / p, 2)
    return f"{s} {size_name[i]}"

# --- Network Communication with Framing ---
def send_framed_message(sock, message_dict):
    message_json = json.dumps(message_dict).encode('utf-8')
    header = struct.pack('!I', len(message_json))
    sock.sendall(header + message_json)

def receive_framed_message(sock):
    header_data = sock.recv(4)
    if not header_data: return None
    message_length = struct.unpack('!I', header_data)[0]
    
    full_message_data = b''
    while len(full_message_data) < message_length:
        chunk = sock.recv(message_length - len(full_message_data))
        if not chunk: return None
        full_message_data += chunk
        
    return json.loads(full_message_data.decode('utf-8'))

# --- Backend Logic Class ---
class SecuriChatClient:
    def __init__(self, username, tracker_addr, ui_queue):
        self.username = username
        self.tracker_ip, self.tracker_port = tracker_addr
        self.ui_queue = ui_queue
        self.private_key, self.public_key = generate_keys()
        self.public_key_pem = serialize_public_key(self.public_key)
        self.p2p_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.p2p_socket.bind(('0.0.0.0', 0))
        self.p2p_ip, self.p2p_port = self.p2p_socket.getsockname()
        self.online_users = {}
        self.running = True
        self.voice_call_instance = None
        self.call_partner = None
        self.incoming_files = {}

    def queue_ui_update(self, command, data):
        self.ui_queue.put((command, data))

    def start(self):
        log_event(f"Client '{self.username}' starting up...")
        if not self.register_with_tracker(): return False
            
        self.update_user_list() 

        threading.Thread(target=self.listen_for_peers, daemon=True).start()
        threading.Thread(target=self.update_user_list_periodically, daemon=True).start()
        log_event(f"P2P listener started on {self.p2p_ip}:{self.p2p_port} using TCP.", level="P2P")
        return True

    def stop(self):
        self.running = False
        if self.voice_call_instance: self.end_voice_call_session(self.call_partner)
        self.deregister_from_tracker()
        self.p2p_socket.close()
        log_event(f"Client '{self.username}' has been stopped.")

    def _send_to_tracker(self, command):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                log_event(f"Connecting to tracker at {self.tracker_ip}:{self.tracker_port} via TCP.", level="NETWORK")
                s.connect((self.tracker_ip, self.tracker_port))
                log_event(f"Sending command '{command['command']}' to tracker.", level="NETWORK")
                send_framed_message(s, command)
                response = receive_framed_message(s)
                log_event(f"Received response from tracker: {response}", level="NETWORK")
                return response
        except Exception as e:
            log_event(f"Error communicating with tracker: {e}", level="ERROR")
            return None

    def register_with_tracker(self):
        command = {"command": "REGISTER", "username": self.username, "port": self.p2p_port, "public_key": self.public_key_pem}
        response = self._send_to_tracker(command)
        if response and response.get("status") == "OK":
            log_event("Successfully registered with tracker."); return True
        else:
            msg = response.get('message') if response else 'Tracker unreachable'
            log_event(f"Failed to register with tracker: {msg}", level="ERROR")
            self.queue_ui_update("show_error", f"Failed to register: {msg}"); return False

    def deregister_from_tracker(self):
        self._send_to_tracker({"command": "DEREGISTER", "username": self.username})
        log_event("Deregistered from tracker.")

    def update_user_list(self):

        response = self._send_to_tracker({"command": "GET_USERS", "username": self.username})
        if response is not None:
            self.online_users = response
            self.queue_ui_update("update_user_list", self.online_users)

    def update_user_list_periodically(self):
        while self.running:
            # The periodic updater now just calls the single-use method
            self.update_user_list()
            time.sleep(10)

    def listen_for_peers(self):
        self.p2p_socket.listen(10)
        while self.running:
            try:
                conn, addr = self.p2p_socket.accept()
                log_event(f"Accepted incoming P2P connection from {addr} via TCP.", level="P2P")
                threading.Thread(target=self.handle_peer_connection, args=(conn,), daemon=True).start()
            except OSError: break

    def handle_peer_connection(self, conn):
        try:
            while self.running:
                message = receive_framed_message(conn)
                if not message:
                    log_event(f"Peer at {conn.getpeername()} closed the connection.", level="P2P")
                    break
                
                log_event(f"Received an onion-wrapped message from {conn.getpeername()}.", level="P2P")
                path = message.get('path')
                if not path:
                    log_event(f"Received message with no path. Discarding.", level="ERROR"); continue

                # --- Onion Decryption: Layer 1 ---
                log_event("Starting Onion Decryption Process.", level="CRYPTO")
                encrypted_sym_key_b64 = message['sym_key']
                encrypted_sym_key = base64.b64decode(encrypted_sym_key_b64)
                log_event("Decrypting symmetric key with my private key (RSA-OAEP).", level="CRYPTO")
                sym_key = self.private_key.decrypt(encrypted_sym_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
                
                fernet = Fernet(sym_key)
                encrypted_payload_b64 = message['payload']
                decrypted_payload = fernet.decrypt(base64.b64decode(encrypted_payload_b64))
                inner_message = json.loads(decrypted_payload.decode('utf-8'))
                log_event("Successfully decrypted one layer of the onion message.", level="CRYPTO")

                if inner_message['destination_user'] == self.username:
                    log_event(f"Message is for me. Final destination reached. Path: {path}", level="P2P")
                    self.process_final_message(inner_message)
                else:
                    log_event(f"Message is not for me. Relaying to next hop: {inner_message['destination_user']}. Path: {path}", level="P2P")
                    self.relay_message(inner_message, path)
        except Exception as e:
            log_event(f"Error in handle_peer_connection: {type(e).__name__}: {e}", level="ERROR")
        finally:
            conn.close()

    def process_final_message(self, message):
        sender, msg_type, content = message['sender_user'], message['type'], message['content']
        
        # --- Error Detection: Checksum Verification ---
        log_event(f"Processing final message of type '{msg_type}' from '{sender}'.", level="INFO")
        log_event("Performing checksum verification for data integrity.", level="INFO")
        calculated_checksum = hashlib.sha256(str(content).encode('utf-8')).hexdigest()
        if message.get('checksum') != calculated_checksum:
            log_event(f"Checksum MISMATCH for message from {sender}. Data may be corrupt.", level="ERROR")
            content = f"[CHECKSUM FAILED] {content}"
        else:
            log_event(f"Checksum VERIFIED for message from {sender}. Data is intact.", level="INFO")

        if msg_type == "text": self.queue_ui_update("receive_message", (sender, content))
        elif msg_type == "call_request": self.queue_ui_update("incoming_call", (sender, int(content)))
        elif msg_type == "call_accepted": self.start_voice_call_session(sender, int(content), is_initiator=True)
        elif msg_type == "call_ended": self.end_voice_call_session(sender, initiated_by_other=True)
        elif msg_type == "file_start": self.handle_file_start(sender, content)
        elif msg_type == "file_chunk": self.handle_file_chunk(sender, content)
        elif msg_type == "file_end": self.handle_file_end(sender, content)

    def relay_message(self, inner_message, original_path):
        next_hop_user = inner_message['destination_user']
        if next_hop_user in self.online_users:
            next_hop_info = self.online_users[next_hop_user]
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as relay_socket:
                    log_event(f"Connecting to next hop '{next_hop_user}' at {next_hop_info['ip']}:{next_hop_info['port']} via TCP.", level="NETWORK")
                    relay_socket.connect((next_hop_info['ip'], next_hop_info['port']))
                    message_to_forward = inner_message['payload']
                    message_to_forward['path'] = original_path
                    send_framed_message(relay_socket, message_to_forward)
                    log_event(f"Successfully relayed message to {next_hop_user}", level="P2P")
            except Exception as e:
                log_event(f"Failed to relay message to {next_hop_user}: {e}", level="ERROR")
        else:
            log_event(f"Cannot relay message: Next hop user '{next_hop_user}' is offline.", level="ERROR")

    def _send_onion_message(self, sock, recipient_user, message_content, msg_type):
        # --- Onion Encryption Process ---
        log_event(f"Starting Onion Encryption for a '{msg_type}' message to '{recipient_user}'.", level="CRYPTO")
        
        # For simplicity, this implementation uses a 2-hop path (sender -> relay -> recipient)
        available_relays = [u for u in self.online_users if u != recipient_user and u != self.username]
        if not available_relays:
            log_event("Cannot create onion path: Not enough online users to act as a relay.", level="ERROR")
            self.queue_ui_update("show_error", "Cannot send message: At least 3 users must be online for a relay path."); return False

        relay_user = random.choice(available_relays)
        path = [self.username, relay_user, recipient_user]
        log_event(f"Selected onion path: {' -> '.join(path)}", level="CRYPTO")

        # --- Layer 1: For the final recipient ---
        log_event(f"Creating innermost layer for recipient '{recipient_user}'.", level="CRYPTO")
        checksum = hashlib.sha256(str(message_content).encode('utf-8')).hexdigest()
        log_event(f"Generated SHA-256 checksum for content: {checksum}", level="CRYPTO")
        final_payload = json.dumps({"sender_user": self.username, "destination_user": recipient_user, "type": msg_type, "content": message_content, "checksum": checksum}).encode('utf-8')
        
        recipient_pk = deserialize_public_key(self.online_users[recipient_user]['public_key'])
        sym_key_for_recipient = Fernet.generate_key()
        log_event("Generated Fernet symmetric key for recipient.", level="CRYPTO")
        encrypted_payload = Fernet(sym_key_for_recipient).encrypt(final_payload)
        log_event("Encrypted final payload with symmetric key.", level="CRYPTO")
        
        encrypted_sym_key_for_recipient = recipient_pk.encrypt(sym_key_for_recipient, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        log_event("Encrypted symmetric key with recipient's public key (RSA-OAEP).", level="CRYPTO")
        
        current_package = {
            "sym_key": base64.b64encode(encrypted_sym_key_for_recipient).decode('utf-8'),
            "payload": base64.b64encode(encrypted_payload).decode('utf-8')
        }

        # --- Layer 2: For the relay node ---
        log_event(f"Creating outer layer for relay '{relay_user}'.", level="CRYPTO")
        relay_payload = json.dumps({"destination_user": recipient_user, "payload": current_package}).encode('utf-8')
        
        relay_pk = deserialize_public_key(self.online_users[relay_user]['public_key'])
        sym_key_for_relay = Fernet.generate_key()
        log_event("Generated Fernet symmetric key for relay.", level="CRYPTO")
        encrypted_relay_payload = Fernet(sym_key_for_relay).encrypt(relay_payload)
        log_event("Encrypted relay payload with symmetric key.", level="CRYPTO")

        encrypted_sym_key_for_relay = relay_pk.encrypt(sym_key_for_relay, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        log_event("Encrypted symmetric key with relay's public key (RSA-OAEP).", level="CRYPTO")

        outer_message = {
            "path": " -> ".join(path),
            "sym_key": base64.b64encode(encrypted_sym_key_for_relay).decode('utf-8'),
            "payload": base64.b64encode(encrypted_relay_payload).decode('utf-8')
        }
        
        log_event("Onion encryption complete. Sending message.", level="CRYPTO")
        send_framed_message(sock, outer_message)
        return True

    def send_message(self, recipient_user, message_content, msg_type="text"):
        if recipient_user not in self.online_users:
            log_event(f"Send failed: User '{recipient_user}' is offline.", level="ERROR")
            self.queue_ui_update("show_error", f"Cannot send message. User '{recipient_user}' is offline."); return
        try:
            # The first hop is the relay node
            first_hop_user = random.choice([u for u in self.online_users if u != recipient_user and u != self.username])
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                log_event(f"Opening TCP connection to first hop '{first_hop_user}' to send a message.", level="NETWORK")
                s.connect((self.online_users[first_hop_user]['ip'], self.online_users[first_hop_user]['port']))
                self._send_onion_message(s, recipient_user, message_content, msg_type)
            log_event(f"Message sent to first hop: {first_hop_user}", level="P2P")
        except IndexError:
             log_event("Cannot send message: Not enough users online for a relay.", level="ERROR")
             self.queue_ui_update("show_error", "Cannot send message: At least 3 users must be online.")
        except Exception as e:
            log_event(f"Error sending single message: {e}", level="ERROR")

    def start_file_send_chunked(self, recipient, filepath):
        if recipient not in self.online_users:
            log_event(f"File send failed: User '{recipient}' is offline.", level="ERROR")
            self.queue_ui_update("show_error", f"Cannot send file. User '{recipient}' is offline."); return
        try:
            filesize = os.path.getsize(filepath)
            filename = os.path.basename(filepath)
            chunk_count = math.ceil(filesize / FILE_CHUNK_SIZE)
            transfer_id = f"{filename}_{time.time()}"
            
            log_event(f"Initiating file transfer of '{filename}' ({format_filesize(filesize)}) to '{recipient}'.", level="INFO")
            
            first_hop_user = random.choice([u for u in self.online_users if u != recipient and u != self.username])
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                log_event(f"Opening persistent TCP connection to relay '{first_hop_user}' for file transfer.", level="NETWORK")
                s.connect((self.online_users[first_hop_user]['ip'], self.online_users[first_hop_user]['port']))
                
                # Send file start message
                start_info = {"transfer_id": transfer_id, "filename": filename, "filesize": filesize, "chunk_count": chunk_count}
                log_event(f"Sending 'file_start' message for transfer ID {transfer_id}.", level="P2P")
                if not self._send_onion_message(s, recipient, start_info, "file_start"): return
                self.queue_ui_update("file_transfer_update", ("start_send", recipient, start_info))

                # Send file chunks
                with open(filepath, "rb") as f:
                    for i in range(chunk_count):
                        if not self.running: log_event("File transfer cancelled by user.", level="INFO"); return
                        chunk_data = f.read(FILE_CHUNK_SIZE)
                        chunk_info = {"transfer_id": transfer_id, "chunk_index": i, "data": base64.b64encode(chunk_data).decode('utf-8')}
                        if (i == 0 or (i+1) % 10 == 0 or i+1 == chunk_count): # Log first, last, and every 10th chunk
                            log_event(f"Sending chunk {i+1}/{chunk_count} for transfer ID {transfer_id}.", level="P2P")
                        if not self._send_onion_message(s, recipient, chunk_info, "file_chunk"): return
                        self.queue_ui_update("file_transfer_update", ("progress", recipient, {"transfer_id": transfer_id, "chunk_index": i}))

                # Send file end message
                end_info = {"transfer_id": transfer_id, "filename": filename}
                log_event(f"Sending 'file_end' message for transfer ID {transfer_id}.", level="P2P")
                self._send_onion_message(s, recipient, end_info, "file_end")
                log_event(f"Finished sending all file data to relay '{first_hop_user}'.", level="INFO")
        except IndexError:
             log_event("Cannot send file: Not enough users online for a relay.", level="ERROR")
             self.queue_ui_update("show_error", "Cannot send file: At least 3 users must be online.")
        except Exception as e:
            log_event(f"Error sending file: {e}", level="ERROR")

    def handle_file_start(self, sender, content):
        log_event(f"Received 'file_start' from '{sender}' for file '{content['filename']}'.", level="P2P")
        self.queue_ui_update("incoming_file", (sender, content))

    def handle_file_chunk(self, sender, content):
        transfer_id = content['transfer_id']
        if transfer_id in self.incoming_files:
            transfer_info = self.incoming_files[transfer_id]
            chunk_data = base64.b64decode(content['data'])
            transfer_info['file'].write(chunk_data)
            transfer_info['received_chunks'] += 1
            idx = content['chunk_index']
            total = transfer_info['total_chunks']
            if (idx == 0 or (idx+1) % 10 == 0 or idx+1 == total):
                 log_event(f"Received and wrote chunk {idx+1}/{total} for file '{transfer_info['path']}'.", level="P2P")
            self.queue_ui_update("file_transfer_update", ("progress", sender, {"transfer_id": transfer_id, "chunk_index": idx}))

    def handle_file_end(self, sender, content):
        transfer_id = content['transfer_id']
        if transfer_id in self.incoming_files:
            log_event(f"Received 'file_end' from '{sender}' for file '{content['filename']}'.", level="P2P")
            self.incoming_files[transfer_id]['file'].close()
            log_event(f"File '{self.incoming_files[transfer_id]['path']}' has been completely received and saved.", level="INFO")
            self.queue_ui_update("file_transfer_update", ("finish_recv", sender, content))
            del self.incoming_files[transfer_id]

    def initiate_voice_call(self, target_user):
        if not VOICE_CALL_ENABLED or self.voice_call_instance: return
        if target_user not in self.online_users:
            self.queue_ui_update("show_error", f"Cannot call. User '{target_user}' is offline."); return
        log_event(f"Initiating voice call with '{target_user}'. Sending 'call_request' via Onion/TCP.", level="INFO")
        self.call_partner = target_user
        # The call request is sent as a standard onion message
        self.send_message(target_user, str(self.p2p_port + 1), msg_type="call_request")

    def accept_voice_call(self, target_user, target_udp_port):
        if not VOICE_CALL_ENABLED or self.voice_call_instance: return
        log_event(f"Accepting voice call from '{target_user}'. Sending 'call_accepted' via Onion/TCP.", level="INFO")
        self.call_partner = target_user
        self.send_message(target_user, str(self.p2p_port + 1), msg_type="call_accepted")
        self.start_voice_call_session(target_user, target_udp_port, is_initiator=False)

    def start_voice_call_session(self, target_user, target_udp_port, is_initiator):
        if not VOICE_CALL_ENABLED or self.voice_call_instance: return
        target_ip = self.online_users[target_user]['ip']
        my_udp_port = self.p2p_port + 1
        log_event(f"Starting voice call session with {target_user} ({target_ip}:{target_udp_port}).", level="INFO")
        log_event(f"Protocol: UDP. My listening port: {my_udp_port}. Target port: {target_udp_port}.", level="NETWORK")
        self.voice_call_instance = VoiceCall(target_ip, target_udp_port, my_udp_port)
        if self.voice_call_instance.start():
            log_event("Voice call streams (PyAudio) and UDP socket started successfully.", level="INFO")
            self.queue_ui_update("call_started", target_user)
        else:
            log_event("Failed to start voice call session.", level="ERROR")
            self.voice_call_instance = None

    def end_voice_call_session(self, target_user, initiated_by_other=False):
        call_instance_to_end = self.voice_call_instance
        if not VOICE_CALL_ENABLED or not call_instance_to_end: return
        
        user_in_call = target_user or self.call_partner
        if not user_in_call: return

        self.voice_call_instance = None
        self.call_partner = None
        
        if not initiated_by_other:
            log_event(f"Ending voice call with '{user_in_call}'. Sending 'call_ended' message via Onion/TCP.", level="INFO")
            self.send_message(user_in_call, "ended", msg_type="call_ended")
        else:
            log_event(f"Received 'call_ended' message from '{user_in_call}'.", level="INFO")
        
        call_instance_to_end.stop()
        duration = call_instance_to_end.get_duration()
        
        log_event(f"Voice call with {user_in_call} ended. UDP socket and streams closed. Duration: {duration:.2f}s", level="INFO")
        self.queue_ui_update("call_ended", (user_in_call, duration))

# --- GUI Application Class (No changes needed below this line) ---
class SecuriChatGUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("SecuriChat")
        self.geometry("300x250")
        self.client_backend = None
        self.chat_sessions = {}
        self.current_chat_user = None
        self.history_file = ""
        self.unread_notifications = set()
        self.transfer_widgets = {}
        self.ui_queue = queue.Queue()
        self.create_login_widgets()
        self.after(100, self.process_ui_queue)

    def process_ui_queue(self):
        try:
            while True:
                command, data = self.ui_queue.get_nowait()
                self.handle_backend_callback(command, data)
        except queue.Empty:
            pass
        self.after(100, self.process_ui_queue)

    def load_history(self):
        self.history_file = f"history_{self.client_backend.username}.json"
        try:
            if os.path.exists(self.history_file):
                with open(self.history_file, 'r') as f:
                    loaded_sessions = json.load(f)
                    for user, messages in loaded_sessions.items():
                        self.chat_sessions[user] = [
                            (msg[0], msg[1], msg[2] if len(msg) == 3 else None) for msg in messages
                        ]
                log_event("Chat history loaded from file.", level="INFO")
        except (json.JSONDecodeError, FileNotFoundError) as e:
            log_event(f"Could not load chat history: {e}", level="ERROR")
            self.chat_sessions = {}

    def save_history(self):
        if self.history_file:
            with open(self.history_file, 'w') as f:
                json.dump(self.chat_sessions, f, indent=4)
            log_event("Chat history saved to file.", level="INFO")

    def create_login_widgets(self):
        self.login_frame = ctk.CTkFrame(self)
        self.login_frame.pack(pady=20, padx=20, fill="both", expand=True)
        ctk.CTkLabel(self.login_frame, text="SecuriChat Login", font=ctk.CTkFont(size=16, weight="bold")).pack(pady=(10, 15))
        self.username_entry = ctk.CTkEntry(self.login_frame, placeholder_text="Username")
        self.username_entry.pack(pady=5, padx=10)
        self.tracker_entry = ctk.CTkEntry(self.login_frame, placeholder_text="Tracker IP:Port")
        self.tracker_entry.insert(0, "127.0.0.1:8000")
        self.tracker_entry.pack(pady=5, padx=10)
        self.login_button = ctk.CTkButton(self.login_frame, text="Login", command=self.login)
        self.login_button.pack(pady=20, padx=10)

    def login(self):
        username = self.username_entry.get()
        tracker_addr_str = self.tracker_entry.get()
        if not username or not tracker_addr_str:
            messagebox.showerror("Error", "Username and Tracker address are required."); return
        
        try:
            ip, port_str = tracker_addr_str.split(":")
            tracker_addr = (ip, int(port_str))
        except ValueError:
            messagebox.showerror("Error", "Invalid Tracker address format. Use IP:Port."); return

        self.client_backend = SecuriChatClient(username, tracker_addr, self.ui_queue)
        self.load_history()
        if self.client_backend.start():
            self.login_frame.destroy()
            self.create_main_widgets()
            self.protocol("WM_DELETE_WINDOW", self.on_closing)
        else:
            self.client_backend = None

    def create_main_widgets(self):
        self.title(f"SecuriChat - {self.client_backend.username}")
        self.geometry("900x600")

        self.user_frame = ctk.CTkFrame(self, width=250)
        self.user_frame.pack(side="left", fill="y", expand=False, padx=(10, 5), pady=10)
        
        self.main_chat_frame = ctk.CTkFrame(self)
        self.main_chat_frame.pack(side="right", fill="both", expand=True, padx=(5, 10), pady=10)

        ctk.CTkLabel(self.user_frame, text="Chat History", font=ctk.CTkFont(size=16, weight="bold")).pack(pady=(10,0), padx=10)
        self.history_listbox = ctk.CTkScrollableFrame(self.user_frame, label_text="")
        self.history_listbox.pack(fill="both", expand=True, padx=5, pady=5)

        ctk.CTkLabel(self.user_frame, text="Online Users", font=ctk.CTkFont(size=16, weight="bold")).pack(pady=(10,0), padx=10)
        self.online_listbox = ctk.CTkScrollableFrame(self.user_frame, label_text="")
        self.online_listbox.pack(fill="both", expand=True, padx=5, pady=5)

        self.welcome_label = ctk.CTkLabel(self.main_chat_frame, text="Select a user to start chatting.", font=ctk.CTkFont(size=20))
        self.welcome_label.pack(pady=100, padx=20)

        self.update_history_list_display()

    def handle_backend_callback(self, command, data):
        if command == "update_user_list": self.update_online_list_display(data)
        elif command == "receive_message": self.display_received_message(*data)
        elif command == "show_error": messagebox.showerror("Client Error", data)
        elif command == "incoming_call":
            sender, udp_port = data
            if messagebox.askyesno("Incoming Call", f"Incoming call from {sender}. Accept?"):
                self.client_backend.accept_voice_call(sender, udp_port)
        elif command == "call_started": self.update_call_status(data, True)
        elif command == "call_ended":
            user, duration = data
            self.update_call_status(user, False)
            self.log_call_in_chat(user, duration)
        elif command == "incoming_file":
            sender, file_info = data
            if messagebox.askyesno("File Transfer", f"Accept file '{file_info['filename']}' ({format_filesize(file_info['filesize'])}) from {sender}?"):
                save_path = filedialog.asksaveasfilename(initialfile=file_info['filename'])
                if save_path:
                    self.client_backend.incoming_files[file_info['transfer_id']] = {"path": save_path, "received_chunks": 0, "total_chunks": file_info['chunk_count'], "file": open(save_path, "wb")}
                    self.handle_file_ui_update("start_recv", sender, file_info)
        elif command == "file_transfer_update":
            event_type, peer, info = data
            self.handle_file_ui_update(event_type, peer, info)

    def update_history_list_display(self):
        for widget in self.history_listbox.winfo_children():
            try: widget.destroy()
            except ctk.TclError: pass
        for username in sorted(self.chat_sessions.keys()):
            btn = ctk.CTkButton(self.history_listbox, text=username, command=lambda u=username: self.switch_chat_view(u))
            btn.pack(fill="x", pady=2, padx=2)

    def update_online_list_display(self, user_dict):
        if not hasattr(self, 'online_listbox') or not self.online_listbox.winfo_exists():
            self.after(100, lambda: self.update_online_list_display(user_dict)); return
        try:
            current_buttons = {child.cget("text"): child for child in self.online_listbox.winfo_children()}
            online_users = set(user_dict.keys())
            
            for user, button in list(current_buttons.items()):
                if user not in online_users:
                    try: button.destroy()
                    except (ctk.TclError, RuntimeError): pass
            for user in online_users:
                if user not in current_buttons:
                    btn = ctk.CTkButton(self.online_listbox, text=user, command=lambda u=user: self.switch_chat_view(u))
                    btn.pack(fill="x", pady=2, padx=2)
                else:
                    btn = current_buttons[user]
                
                if user in self.unread_notifications:
                    btn.configure(fg_color="green")
                else:
                    btn.configure(fg_color=("#3a7ebf", "#1f538d"))
        except Exception as e:
            log_event(f"GUI Error in update_online_list_display: {e}", level="ERROR")

    def switch_chat_view(self, username):
        self.current_chat_user = username
        self.unread_notifications.discard(username)
        self.update_online_list_display(self.client_backend.online_users)
        
        for widget in self.main_chat_frame.winfo_children(): widget.destroy()

        self.chat_text_area = ctk.CTkTextbox(self.main_chat_frame, state="disabled", wrap="word")
        self.chat_text_area.pack(side="top", fill="both", expand=True, padx=10, pady=(10, 5))
        
        received_text_color = "white" if ctk.get_appearance_mode() == "Dark" else "black"
        self.chat_text_area.tag_config("sent", foreground="#C39BD3")
        self.chat_text_area.tag_config("received", foreground=received_text_color)
        self.chat_text_area.tag_config("system", foreground="gray", justify="center")
        self.chat_text_area.tag_config("file", foreground="#3498DB")

        self.progress_frame = ctk.CTkFrame(self.main_chat_frame, fg_color="transparent")
        self.progress_frame.pack(side="bottom", fill="x", padx=10)

        input_frame = ctk.CTkFrame(self.main_chat_frame, fg_color="transparent")
        input_frame.pack(side="bottom", fill="x", expand=False, padx=10, pady=(5, 10))

        self.message_entry = ctk.CTkEntry(input_frame, placeholder_text=f"Message {username}...")
        self.message_entry.pack(side="left", fill="x", expand=True)
        self.message_entry.bind("<Return>", lambda e: self.send_chat_message())

        self.send_button = ctk.CTkButton(input_frame, text="Send", width=70, command=self.send_chat_message)
        self.send_button.pack(side="left", padx=(5, 0))
        
        self.file_button = ctk.CTkButton(input_frame, text="📎 File", width=70, command=self.on_send_file_click)
        self.file_button.pack(side="left", padx=5)
        
        self.call_button = ctk.CTkButton(input_frame, text="📞 Call", width=70, command=self.toggle_call, state="normal" if VOICE_CALL_ENABLED else "disabled")
        self.call_button.pack(side="left", padx=5)

        self.load_chat_history(username)
        self.update_call_status(username, self.client_backend.call_partner == username)

    def load_chat_history(self, username):
        self.chat_text_area.configure(state="normal")
        self.chat_text_area.delete("1.0", "end")
        for item in self.chat_sessions.get(username, []):
            if len(item) == 3:
                msg_type, text, data = item
            else:
                msg_type, text = item; data = None
            self.add_message_to_box(text, msg_type, data)
        self.chat_text_area.configure(state="disabled")

    def send_chat_message(self):
        message = self.message_entry.get()
        if message and self.current_chat_user:
            if self.current_chat_user not in self.client_backend.online_users:
                messagebox.showerror("Offline", f"User '{self.current_chat_user}' is offline. Cannot send message.")
                return
            self.client_backend.send_message(self.current_chat_user, message)
            self.add_message_to_session(self.current_chat_user, "sent", f"You: {message}")
            self.message_entry.delete(0, "end")

    def display_received_message(self, sender, message):
        self.add_message_to_session(sender, "received", f"{sender}: {message}")
        if sender != self.current_chat_user:
            self.unread_notifications.add(sender)
            self.update_online_list_display(self.client_backend.online_users)
            messagebox.showinfo("New Message", f"You have a new message from {sender}.")

    def add_message_to_session(self, username, msg_type, text, data=None):
        if username not in self.chat_sessions: self.chat_sessions[username] = []
        self.chat_sessions[username].append((msg_type, text, data))
        if self.current_chat_user == username:
            self.add_message_to_box(text, msg_type, data)
        self.update_history_list_display()

    def add_message_to_box(self, text, tag, data=None):
        if not hasattr(self, 'chat_text_area') or not self.chat_text_area.winfo_exists(): return
        self.chat_text_area.configure(state="normal")
        self.chat_text_area.insert("end", text + "\n", tag)
        self.chat_text_area.configure(state="disabled")
        self.chat_text_area.see("end")

    def on_send_file_click(self):
        if self.current_chat_user:
            if self.current_chat_user not in self.client_backend.online_users:
                messagebox.showerror("Offline", f"User '{self.current_chat_user}' is offline. Cannot send file."); return
            filepath = filedialog.askopenfilename()
            if filepath:
                threading.Thread(target=self.client_backend.start_file_send_chunked, args=(self.current_chat_user, filepath), daemon=True).start()

    def toggle_call(self):
        if self.current_chat_user:
            if self.client_backend.voice_call_instance:
                self.client_backend.end_voice_call_session(self.current_chat_user)
            else:
                self.client_backend.initiate_voice_call(self.current_chat_user)

    def update_call_status(self, username, in_call):
        if self.current_chat_user == username and hasattr(self, 'call_button'):
            self.call_button.configure(text="End Call" if in_call else "📞 Call", fg_color="red" if in_call else ("#3a7ebf", "#1f538d"))

    def log_call_in_chat(self, username, duration):
        log_text = f"--- Voice call ended at {datetime.now().strftime('%H:%M:%S')}. Duration: {duration:.2f} seconds. ---"
        self.add_message_to_session(username, "system", log_text)

    def handle_file_ui_update(self, event_type, peer, info):
        transfer_id = info['transfer_id']
        if event_type == "start_send":
            text = f"📎 You are sending {info['filename']} ({format_filesize(info['filesize'])})"
            self.add_message_to_session(peer, "file", text, info)
            self.create_progress_bar(transfer_id, info)
        elif event_type == "start_recv":
            text = f"📎 {peer} is sending {info['filename']} ({format_filesize(info['filesize'])})"
            self.add_message_to_session(peer, "file", text, info)
            self.create_progress_bar(transfer_id, info)
        elif event_type == "progress":
            if transfer_id in self.transfer_widgets:
                progress = (info['chunk_index'] + 1) / self.transfer_widgets[transfer_id]['total_chunks']
                self.transfer_widgets[transfer_id]['bar'].set(progress)
        elif event_type == "finish_send":
            self.add_message_to_session(peer, "system", f"✅ Sent {info['filename']} successfully.")
            if transfer_id in self.transfer_widgets:
                self.transfer_widgets[transfer_id]['frame'].destroy()
                del self.transfer_widgets[transfer_id]
        elif event_type == "finish_recv":
            self.add_message_to_session(peer, "system", f"✅ Received {info['filename']} successfully.")
            if transfer_id in self.transfer_widgets:
                self.transfer_widgets[transfer_id]['frame'].destroy()
                del self.transfer_widgets[transfer_id]

    def create_progress_bar(self, transfer_id, file_info):
        if not hasattr(self, 'progress_frame') or not self.progress_frame.winfo_exists(): return
        
        frame = ctk.CTkFrame(self.progress_frame)
        frame.pack(fill="x", expand=True, pady=2, padx=2)
        
        label = ctk.CTkLabel(frame, text=f"{file_info['filename']}")
        label.pack(side="left", padx=5)
        
        bar = ctk.CTkProgressBar(frame)
        bar.set(0)
        bar.pack(side="left", fill="x", expand=True, padx=5)
        
        self.transfer_widgets[transfer_id] = {"frame": frame, "bar": bar, "total_chunks": file_info['chunk_count']}

    def on_closing(self):
        self.save_history()
        if self.client_backend: self.client_backend.stop()
        self.destroy()

if __name__ == "__main__":
    # Clear the log file on startup for a clean run
    if os.path.exists(LOG_FILE):
        os.remove(LOG_FILE)
    ctk.set_appearance_mode("System")
    ctk.set_default_color_theme("blue")
    app = SecuriChatGUI()
    app.mainloop()