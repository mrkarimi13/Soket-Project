# client.py (Final Version with All Features)
import customtkinter as ctk
import socket
import threading
import json
import time
import random
import hashlib
import base64
import os
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
P2P_BUFFER_SIZE = 8192
TRACKER_BUFFER_SIZE = 4096
LOG_FILE = "report.log"
FILE_CHUNK_SIZE = 4096

# --- Utility Functions ---
def log_event(message):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_message = f"[{timestamp}] {message}\n"
    print(log_message.strip())
    with open(LOG_FILE, "a", encoding='utf-8') as f:
        f.write(log_message)

def generate_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key, private_key.public_key()

def serialize_public_key(public_key):
    return public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode('utf-8')

def deserialize_public_key(pem_data):
    return serialization.load_pem_public_key(pem_data.encode('utf-8'))

# --- Backend Logic Class ---
class SecuriChatClient:
    def __init__(self, username, tracker_addr, gui_callback):
        self.username = username
        self.tracker_ip, self.tracker_port = tracker_addr
        self.gui_callback = gui_callback
        self.private_key, self.public_key = generate_keys()
        self.public_key_pem = serialize_public_key(self.public_key)
        self.p2p_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.p2p_socket.bind(('0.0.0.0', 0))
        self.p2p_ip, self.p2p_port = self.p2p_socket.getsockname()
        self.online_users = {}
        self.running = True
        self.voice_call_instance = None
        self.call_partner = None

    def start(self):
        if not self.register_with_tracker(): return False
        threading.Thread(target=self.listen_for_peers, daemon=True).start()
        threading.Thread(target=self.update_user_list_periodically, daemon=True).start()
        log_event(f"Client '{self.username}' started. Listening for P2P on {self.p2p_ip}:{self.p2p_port}")
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
                s.connect((self.tracker_ip, self.tracker_port))
                s.sendall(json.dumps(command).encode('utf-8'))
                return json.loads(s.recv(TRACKER_BUFFER_SIZE).decode('utf-8'))
        except Exception as e:
            log_event(f"Error communicating with tracker: {e}")
            return None

    def register_with_tracker(self):
        command = {"command": "REGISTER", "username": self.username, "port": self.p2p_port, "public_key": self.public_key_pem}
        response = self._send_to_tracker(command)
        if response and response.get("status") == "OK":
            log_event("Successfully registered with tracker."); return True
        else:
            msg = response.get('message') if response else 'Tracker unreachable'
            log_event(f"Failed to register with tracker: {msg}")
            self.gui_callback("show_error", f"Failed to register: {msg}"); return False

    def deregister_from_tracker(self):
        self._send_to_tracker({"command": "DEREGISTER", "username": self.username})
        log_event("Deregistered from tracker.")

    def update_user_list_periodically(self):
        while self.running:
            response = self._send_to_tracker({"command": "GET_USERS", "username": self.username})
            if response is not None:
                self.online_users = response
                self.gui_callback("update_user_list", self.online_users)
            time.sleep(10)

    def listen_for_peers(self):
        self.p2p_socket.listen(10)
        while self.running:
            try:
                conn, addr = self.p2p_socket.accept()
                log_event(f"Accepted P2P connection from {addr}")
                threading.Thread(target=self.handle_peer_connection, args=(conn,), daemon=True).start()
            except OSError: break

    def handle_peer_connection(self, conn):
        try:
            data = conn.recv(P2P_BUFFER_SIZE)
            if not data: return
            
            message = json.loads(data.decode('utf-8'))
            path = message.get('path')
            if not path:
                log_event(f"Received message with no path. Discarding."); return

            encrypted_sym_key = base64.b64decode(message['sym_key'])
            sym_key = self.private_key.decrypt(encrypted_sym_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
            
            fernet = Fernet(sym_key)
            decrypted_payload = fernet.decrypt(base64.b64decode(message['payload']))
            inner_message = json.loads(decrypted_payload.decode('utf-8'))

            if inner_message['destination_user'] == self.username:
                log_event(f"Received final message via path: {path}")
                self.process_final_message(inner_message)
            else:
                log_event(f"Relaying message. Path: {path}")
                self.relay_message(inner_message, path)
        except Exception as e:
            log_event(f"Error in handle_peer_connection: {type(e).__name__}: {e}")
        finally:
            conn.close()

    def process_final_message(self, message):
        sender, msg_type, content = message['sender_user'], message['type'], message['content']
        
        if message.get('checksum') != hashlib.sha256(str(content).encode('utf-8')).hexdigest():
            log_event(f"Checksum MISMATCH for message from {sender}."); content = f"[CHECKSUM FAILED] {content}"
        else:
            log_event(f"Checksum VERIFIED for message from {sender}")

        if msg_type == "text": self.gui_callback("receive_message", (sender, content))
        elif msg_type == "call_request": self.gui_callback("incoming_call", (sender, int(content)))
        elif msg_type == "call_accepted": self.start_voice_call_session(sender, int(content), is_initiator=True)
        elif msg_type == "call_ended": self.end_voice_call_session(sender, initiated_by_other=True)
        elif msg_type == "file_transfer_request":
            file_info = json.loads(content)
            self.gui_callback("incoming_file", (sender, file_info))

    def relay_message(self, inner_message, original_path):
        next_hop_user = inner_message['destination_user']
        if next_hop_user in self.online_users:
            next_hop_info = self.online_users[next_hop_user]
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as relay_socket:
                    relay_socket.connect((next_hop_info['ip'], next_hop_info['port']))
                    message_to_forward = inner_message['payload']
                    message_to_forward['path'] = original_path
                    relay_socket.sendall(json.dumps(message_to_forward).encode('utf-8'))
                    log_event(f"Successfully relayed message to {next_hop_user}")
            except Exception as e:
                log_event(f"Failed to relay message to {next_hop_user}: {e}")

    def send_message(self, recipient_user, message_content, msg_type="text"):
        if recipient_user not in self.online_users:
            self.gui_callback("show_error", f"Cannot send message. User '{recipient_user}' is offline."); return

        available_relays = [u for u in self.online_users if u != recipient_user]
        if not available_relays:
            self.gui_callback("show_error", "Cannot send message: At least 3 users must be online for a relay path."); return

        relay_user = random.choice(available_relays)
        path = [self.username, relay_user, recipient_user]
        log_event(f"Constructing message for {recipient_user} via path: {' -> '.join(path)}")

        final_payload = json.dumps({"sender_user": self.username, "destination_user": recipient_user, "type": msg_type, "content": message_content, "checksum": hashlib.sha256(str(message_content).encode('utf-8')).hexdigest()}).encode('utf-8')
        recipient_pk = deserialize_public_key(self.online_users[recipient_user]['public_key'])
        sym_key_for_recipient = Fernet.generate_key()
        encrypted_payload = Fernet(sym_key_for_recipient).encrypt(final_payload)
        current_package = {"sym_key": base64.b64encode(recipient_pk.encrypt(sym_key_for_recipient, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))).decode('utf-8'), "payload": base64.b64encode(encrypted_payload).decode('utf-8')}
        relay_payload = json.dumps({"destination_user": recipient_user, "payload": current_package}).encode('utf-8')
        relay_pk = deserialize_public_key(self.online_users[relay_user]['public_key'])
        sym_key_for_relay = Fernet.generate_key()
        encrypted_relay_payload = Fernet(sym_key_for_relay).encrypt(relay_payload)
        outer_message = {"path": " -> ".join(path), "sym_key": base64.b64encode(relay_pk.encrypt(sym_key_for_relay, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))).decode('utf-8'), "payload": base64.b64encode(encrypted_relay_payload).decode('utf-8')}

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((self.online_users[relay_user]['ip'], self.online_users[relay_user]['port']))
                s.sendall(json.dumps(outer_message).encode('utf-8'))
            log_event(f"Message sent to first hop: {relay_user}")
        except Exception as e:
            log_event(f"Error sending message to first hop {relay_user}: {e}")
            self.gui_callback("show_error", f"Failed to send message: {e}")

    def start_file_send(self, recipient, filepath):
        try:
            filesize = os.path.getsize(filepath)
            filename = os.path.basename(filepath)
            
            # 1. Create a temporary listening socket for the file transfer
            file_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            file_socket.bind(('0.0.0.0', 0))
            file_port = file_socket.getsockname()[1]
            file_socket.listen(1)

            # 2. Send the file transfer request
            file_info = json.dumps({"filename": filename, "filesize": filesize, "port": file_port})
            self.send_message(recipient, file_info, "file_transfer_request")
            
            log_event(f"Waiting for {recipient} to connect for file transfer on port {file_port}...")
            conn, addr = file_socket.accept()
            log_event(f"{recipient} connected for file transfer.")
            
            self.gui_callback("transfer_started", (filename, filesize))
            with open(filepath, "rb") as f:
                bytes_sent = 0
                while True:
                    chunk = f.read(FILE_CHUNK_SIZE)
                    if not chunk: break
                    conn.sendall(chunk)
                    bytes_sent += len(chunk)
                    self.gui_callback("transfer_progress", (filename, bytes_sent))
            
            log_event(f"File '{filename}' sent successfully to {recipient}.")
            self.gui_callback("transfer_finished", (filename, "Sent"))
        except Exception as e:
            log_event(f"Error sending file: {e}")
            self.gui_callback("transfer_finished", (filename, f"Failed: {e}"))
        finally:
            if 'file_socket' in locals(): file_socket.close()

    def start_file_receive(self, sender, file_info, save_path):
        try:
            filename = file_info['filename']
            filesize = file_info['filesize']
            
            target_ip = self.online_users[sender]['ip']
            target_port = file_info['port']

            conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            conn.connect((target_ip, target_port))
            
            log_event(f"Connected to {sender} to receive file '{filename}'.")
            self.gui_callback("transfer_started", (filename, filesize))
            with open(save_path, "wb") as f:
                bytes_received = 0
                while bytes_received < filesize:
                    chunk = conn.recv(FILE_CHUNK_SIZE)
                    if not chunk: break
                    f.write(chunk)
                    bytes_received += len(chunk)
                    self.gui_callback("transfer_progress", (filename, bytes_received))
            
            log_event(f"File '{filename}' received successfully.")
            self.gui_callback("transfer_finished", (filename, "Received"))
        except Exception as e:
            log_event(f"Error receiving file: {e}")
            self.gui_callback("transfer_finished", (filename, f"Failed: {e}"))
        finally:
            if 'conn' in locals(): conn.close()

    def initiate_voice_call(self, target_user):
        if not VOICE_CALL_ENABLED or self.voice_call_instance: return
        if target_user not in self.online_users:
            self.gui_callback("show_error", f"Cannot call. User '{target_user}' is offline."); return
        log_event(f"Requesting voice call with {target_user}")
        self.call_partner = target_user
        self.send_message(target_user, str(self.p2p_port + 1), msg_type="call_request")

    def accept_voice_call(self, target_user, target_udp_port):
        if not VOICE_CALL_ENABLED or self.voice_call_instance: return
        log_event(f"Accepting voice call from {target_user}")
        self.call_partner = target_user
        self.send_message(target_user, str(self.p2p_port + 1), msg_type="call_accepted")
        self.start_voice_call_session(target_user, target_udp_port, is_initiator=False)

    def start_voice_call_session(self, target_user, target_udp_port, is_initiator):
        if not VOICE_CALL_ENABLED or self.voice_call_instance: return
        target_ip = self.online_users[target_user]['ip']
        log_event(f"Starting voice call session with {target_user} ({target_ip}:{target_udp_port})")
        self.voice_call_instance = VoiceCall(target_ip, target_udp_port, self.p2p_port + 1)
        if self.voice_call_instance.start():
            self.gui_callback("call_started", target_user)
        else:
            self.voice_call_instance = None

    def end_voice_call_session(self, target_user, initiated_by_other=False):
        call_instance_to_end = self.voice_call_instance
        if not VOICE_CALL_ENABLED or not call_instance_to_end: return
        
        user_in_call = target_user or self.call_partner
        if not user_in_call: return

        self.voice_call_instance = None
        self.call_partner = None
        
        if not initiated_by_other:
            self.send_message(user_in_call, "ended", msg_type="call_ended")
        
        call_instance_to_end.stop()
        duration = call_instance_to_end.get_duration()
        
        log_event(f"Voice call with {user_in_call} ended. Duration: {duration:.2f}s")
        self.gui_callback("call_ended", (user_in_call, duration))

# --- GUI Application Class ---
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
        self.transfer_progress_bars = {}
        self.create_login_widgets()

    def load_history(self):
        self.history_file = f"history_{self.client_backend.username}.json"
        try:
            if os.path.exists(self.history_file):
                with open(self.history_file, 'r') as f:
                    self.chat_sessions = json.load(f)
                log_event("Chat history loaded.")
        except (json.JSONDecodeError, FileNotFoundError) as e:
            log_event(f"Could not load chat history: {e}")
            self.chat_sessions = {}

    def save_history(self):
        if self.history_file:
            with open(self.history_file, 'w') as f:
                json.dump(self.chat_sessions, f, indent=4)
            log_event("Chat history saved.")

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

        self.client_backend = SecuriChatClient(username, tracker_addr, self.handle_backend_callback)
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

        self.progress_frame = ctk.CTkFrame(self.main_chat_frame, fg_color="transparent")
        self.progress_frame.pack(side="bottom", fill="x", pady=5)

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
            if messagebox.askyesno("File Transfer", f"Accept file '{file_info['filename']}' ({file_info['filesize']:,} bytes) from {sender}?"):
                save_path = filedialog.asksaveasfilename(initialfile=file_info['filename'])
                if save_path:
                    threading.Thread(target=self.client_backend.start_file_receive, args=(sender, file_info, save_path), daemon=True).start()
        elif command == "transfer_started": self.create_progress_bar(*data)
        elif command == "transfer_progress": self.update_progress_bar(*data)
        elif command == "transfer_finished": self.remove_progress_bar(*data)

    def update_history_list_display(self):
        for widget in self.history_listbox.winfo_children(): widget.destroy()
        for username in sorted(self.chat_sessions.keys()):
            btn = ctk.CTkButton(self.history_listbox, text=username, command=lambda u=username: self.switch_chat_view(u))
            btn.pack(fill="x", pady=2, padx=2)

    def update_online_list_display(self, user_dict):
        if not hasattr(self, 'online_listbox') or not self.online_listbox.winfo_exists():
            self.after(100, lambda: self.update_online_list_display(user_dict)); return
        try:
            current_buttons = {child.cget("text"): child for child in self.online_listbox.winfo_children()}
            online_users = set(user_dict.keys())
            
            for user, button in current_buttons.items():
                if user not in online_users: button.destroy()
            for user in online_users:
                if user not in current_buttons:
                    btn = ctk.CTkButton(self.online_listbox, text=user, command=lambda u=user: self.switch_chat_view(u))
                    btn.pack(fill="x", pady=2, padx=2)
                    if user in self.unread_notifications:
                        btn.configure(fg_color="green")
        except Exception as e:
            log_event(f"GUI Error in update_online_list_display: {e}")

    def switch_chat_view(self, username):
        self.current_chat_user = username
        self.unread_notifications.discard(username) # Mark as read
        self.update_online_list_display(self.client_backend.online_users) # Redraw to remove notification color
        
        for widget in self.main_chat_frame.winfo_children():
            if widget != self.progress_frame: widget.destroy()

        self.chat_text_area = ctk.CTkTextbox(self.main_chat_frame, state="disabled", wrap="word")
        self.chat_text_area.pack(side="top", fill="both", expand=True, padx=10, pady=(10, 5))
        
        received_text_color = "white" if ctk.get_appearance_mode() == "Dark" else "black"
        self.chat_text_area.tag_config("sent", foreground="#C39BD3")
        self.chat_text_area.tag_config("received", foreground=received_text_color)
        self.chat_text_area.tag_config("system", foreground="gray", justify="center")

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
        for message_type, text in self.chat_sessions.get(username, []):
            self.add_message_to_box(text, message_type)
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
            self.update_online_list_display(self.client_backend.online_users) # Redraw to show notification
            messagebox.showinfo("New Message", f"You have a new message from {sender}.")

    def add_message_to_session(self, username, msg_type, text):
        if username not in self.chat_sessions: self.chat_sessions[username] = []
        self.chat_sessions[username].append((msg_type, text))
        if self.current_chat_user == username:
            self.add_message_to_box(text, msg_type)
        self.update_history_list_display()

    def add_message_to_box(self, text, tag):
        if not hasattr(self, 'chat_text_area') or not self.chat_text_area.winfo_exists(): return
        self.chat_text_area.configure(state="normal")
        self.chat_text_area.insert("end", text + "\n", tag)
        self.chat_text_area.configure(state="disabled")
        self.chat_text_area.see("end")

    def on_send_file_click(self):
        if self.current_chat_user:
            if self.current_chat_user not in self.client_backend.online_users:
                messagebox.showerror("Offline", f"User '{self.current_chat_user}' is offline. Cannot send file.")
                return
            filepath = filedialog.askopenfilename()
            if filepath:
                threading.Thread(target=self.client_backend.start_file_send, args=(self.current_chat_user, filepath), daemon=True).start()

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

    def create_progress_bar(self, filename, filesize):
        bar_frame = ctk.CTkFrame(self.progress_frame)
        bar_frame.pack(fill="x", expand=True, pady=2, padx=2)
        label = ctk.CTkLabel(bar_frame, text=f"{filename} (0%)")
        label.pack(side="left", padx=5)
        bar = ctk.CTkProgressBar(bar_frame)
        bar.pack(side="left", fill="x", expand=True, padx=5)
        bar.set(0)
        self.transfer_progress_bars[filename] = {"bar": bar, "label": label, "frame": bar_frame, "filesize": filesize}

    def update_progress_bar(self, filename, bytes_transferred):
        if filename in self.transfer_progress_bars:
            info = self.transfer_progress_bars[filename]
            progress = bytes_transferred / info['filesize']
            info['bar'].set(progress)
            info['label'].configure(text=f"{filename} ({progress:.0%})")

    def remove_progress_bar(self, filename, status):
        if filename in self.transfer_progress_bars:
            info = self.transfer_progress_bars[filename]
            info['label'].configure(text=f"{filename} - {status}")
            info['bar'].destroy()
            self.after(5000, info['frame'].destroy) # Remove after 5 seconds
            del self.transfer_progress_bars[filename]

    def on_closing(self):
        self.save_history()
        if self.client_backend: self.client_backend.stop()
        self.destroy()

if __name__ == "__main__":
    ctk.set_appearance_mode("System")
    ctk.set_default_color_theme("blue")
    app = SecuriChatGUI()
    app.mainloop()