# client.py (Corrected for GUI Layout & Stability)
import customtkinter as ctk
import socket
import threading
import json
import time
import random
import hashlib
import base64
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
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

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

    def start(self):
        if not self.register_with_tracker():
            return False
        threading.Thread(target=self.listen_for_peers, daemon=True).start()
        threading.Thread(target=self.update_user_list_periodically, daemon=True).start()
        log_event(f"Client '{self.username}' started. Listening for P2P on {self.p2p_ip}:{self.p2p_port}")
        return True

    def stop(self):
        self.running = False
        self.deregister_from_tracker()
        self.p2p_socket.close()
        if self.voice_call_instance:
            self.voice_call_instance.stop()
        log_event(f"Client '{self.username}' has been stopped.")

    def _send_to_tracker(self, command):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((self.tracker_ip, self.tracker_port))
                s.sendall(json.dumps(command).encode('utf-8'))
                response = s.recv(TRACKER_BUFFER_SIZE)
                return json.loads(response.decode('utf-8'))
        except Exception as e:
            log_event(f"Error communicating with tracker: {e}")
            return None

    def register_with_tracker(self):
        command = {"command": "REGISTER", "username": self.username, "port": self.p2p_port, "public_key": self.public_key_pem}
        response = self._send_to_tracker(command)
        if response and response.get("status") == "OK":
            log_event("Successfully registered with tracker.")
            return True
        else:
            msg = response.get('message') if response else 'Tracker unreachable'
            log_event(f"Failed to register with tracker: {msg}")
            self.gui_callback("show_error", f"Failed to register: {msg}")
            return False

    def deregister_from_tracker(self):
        command = {"command": "DEREGISTER", "username": self.username}
        self._send_to_tracker(command)
        log_event("Deregistered from tracker.")

    def update_user_list_periodically(self):
        while self.running:
            command = {"command": "GET_USERS", "username": self.username}
            response = self._send_to_tracker(command)
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
            except OSError:
                break

    def handle_peer_connection(self, conn):
        try:
            data = conn.recv(P2P_BUFFER_SIZE)
            if not data: return
            
            message = json.loads(data.decode('utf-8'))
            path = message.get('path')
            if not path:
                log_event(f"Received message with no path. Discarding. Content: {message}")
                return

            encrypted_sym_key = base64.b64decode(message['sym_key'])
            sym_key = self.private_key.decrypt(
                encrypted_sym_key,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )
            
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
        
        if message.get('checksum') != hashlib.sha256(content.encode('utf-8')).hexdigest():
            log_event(f"Checksum MISMATCH for message from {sender}.")
            content = f"[CHECKSUM FAILED] {content}"
        else:
            log_event(f"Checksum VERIFIED for message from {sender}")

        if msg_type == "text":
            self.gui_callback("receive_message", (sender, content))
        elif msg_type == "call_request":
            self.gui_callback("incoming_call", (sender, int(content)))
        elif msg_type == "call_accepted":
            self.start_voice_call_session(sender, int(content), is_initiator=True)
        elif msg_type == "call_ended":
            self.end_voice_call_session(sender)

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
            log_event(f"Cannot send message: User '{recipient_user}' is not online.")
            return

        available_relays = [u for u in self.online_users if u != recipient_user]
        if not available_relays:
            self.gui_callback("show_error", "Cannot send message: At least 3 users must be online for a relay path.")
            return

        relay_user = random.choice(available_relays)
        path = [self.username, relay_user, recipient_user]
        log_event(f"Constructing message for {recipient_user} via path: {' -> '.join(path)}")

        final_payload = json.dumps({
            "sender_user": self.username, "destination_user": recipient_user,
            "type": msg_type, "content": message_content,
            "checksum": hashlib.sha256(message_content.encode('utf-8')).hexdigest(),
        }).encode('utf-8')

        recipient_pk = deserialize_public_key(self.online_users[recipient_user]['public_key'])
        sym_key_for_recipient = Fernet.generate_key()
        encrypted_payload = Fernet(sym_key_for_recipient).encrypt(final_payload)
        current_package = {
            "sym_key": base64.b64encode(recipient_pk.encrypt(sym_key_for_recipient, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))).decode('utf-8'),
            "payload": base64.b64encode(encrypted_payload).decode('utf-8')
        }

        relay_payload = json.dumps({
            "destination_user": recipient_user,
            "payload": current_package
        }).encode('utf-8')
        
        relay_pk = deserialize_public_key(self.online_users[relay_user]['public_key'])
        sym_key_for_relay = Fernet.generate_key()
        encrypted_relay_payload = Fernet(sym_key_for_relay).encrypt(relay_payload)
        
        outer_message = {
            "path": " -> ".join(path),
            "sym_key": base64.b64encode(relay_pk.encrypt(sym_key_for_relay, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))).decode('utf-8'),
            "payload": base64.b64encode(encrypted_relay_payload).decode('utf-8')
        }

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((self.online_users[relay_user]['ip'], self.online_users[relay_user]['port']))
                s.sendall(json.dumps(outer_message).encode('utf-8'))
            log_event(f"Message sent to first hop: {relay_user}")
        except Exception as e:
            log_event(f"Error sending message to first hop {relay_user}: {e}")
            self.gui_callback("show_error", f"Failed to send message: {e}")

    def initiate_voice_call(self, target_user):
        if not VOICE_CALL_ENABLED: return
        log_event(f"Requesting voice call with {target_user}")
        self.send_message(target_user, str(self.p2p_port + 1), msg_type="call_request")

    def accept_voice_call(self, target_user, target_udp_port):
        if not VOICE_CALL_ENABLED: return
        log_event(f"Accepting voice call from {target_user}")
        self.send_message(target_user, str(self.p2p_port + 1), msg_type="call_accepted")
        self.start_voice_call_session(target_user, target_udp_port, is_initiator=False)

    def start_voice_call_session(self, target_user, target_udp_port, is_initiator):
        if not VOICE_CALL_ENABLED or self.voice_call_instance: return
        target_ip = self.online_users[target_user]['ip']
        log_event(f"Starting voice call session with {target_user} ({target_ip}:{target_udp_port})")
        self.voice_call_instance = VoiceCall(target_ip, target_udp_port, self.p2p_port + 1)
        self.voice_call_instance.start()
        self.gui_callback("call_started", target_user)

    def end_voice_call_session(self, target_user=None):
        if not VOICE_CALL_ENABLED or not self.voice_call_instance: return
        if target_user:
            self.send_message(target_user, "ended", msg_type="call_ended")
        self.voice_call_instance.stop()
        self.voice_call_instance = None
        log_event("Voice call ended.")
        self.gui_callback("call_ended", target_user)

# --- GUI Application Class ---
class SecuriChatGUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("SecuriChat")
        self.geometry("300x250")
        self.client_backend = None
        self.chat_windows = {}
        self.create_login_widgets()

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
            messagebox.showerror("Error", "Username and Tracker address are required.")
            return
        try:
            ip, port = tracker_addr_str.split(":")
            tracker_addr = (ip, int(port))
        except ValueError:
            messagebox.showerror("Error", "Invalid Tracker address format. Use IP:Port.")
            return
        self.client_backend = SecuriChatClient(username, tracker_addr, self.handle_backend_callback)
        if self.client_backend.start():
            self.login_frame.destroy()
            self.create_main_widgets()
            self.protocol("WM_DELETE_WINDOW", self.on_closing)
        else:
            self.client_backend = None

    def create_main_widgets(self):
        self.title(f"SecuriChat - {self.client_backend.username}")
        self.geometry("800x600")

        # **THE FIX**: Use pack consistently for the main window's direct children.
        self.user_frame = ctk.CTkFrame(self, width=200)
        self.user_frame.pack(side="left", fill="y", expand=False, padx=(10, 5), pady=10)
        
        self.main_frame = ctk.CTkFrame(self)
        self.main_frame.pack(side="right", fill="both", expand=True, padx=(5, 10), pady=10)

        # Populate the user frame
        ctk.CTkLabel(self.user_frame, text="Online Users", font=ctk.CTkFont(size=16, weight="bold")).pack(pady=10, padx=10)
        self.user_listbox = ctk.CTkScrollableFrame(self.user_frame)
        self.user_listbox.pack(fill="both", expand=True, padx=5, pady=5)

        # Populate the main frame (placeholder)
        ctk.CTkLabel(self.main_frame, text="Select a user to start chatting.", font=ctk.CTkFont(size=20)).pack(pady=100)

    def handle_backend_callback(self, command, data):
        if command == "update_user_list": self.update_user_list_display(data)
        elif command == "receive_message": self.display_received_message(*data)
        elif command == "show_error": messagebox.showerror("Client Error", data)
        elif command == "incoming_call":
            sender, udp_port = data
            if messagebox.askyesno("Incoming Call", f"Incoming call from {sender}. Accept?"):
                self.client_backend.accept_voice_call(sender, udp_port)
        elif command == "call_started":
            if data in self.chat_windows: self.chat_windows[data].update_call_status(True)
        elif command == "call_ended":
            user_in_call = data if data else next((u for u, w in self.chat_windows.items() if w.in_call), None)
            if user_in_call and user_in_call in self.chat_windows:
                self.chat_windows[user_in_call].update_call_status(False)

    def update_user_list_display(self, user_dict):
        if not hasattr(self, 'user_listbox') or not self.user_listbox.winfo_exists():
            self.after(100, lambda: self.update_user_list_display(user_dict))
            return
        try:
            current_buttons = {child.cget("text"): child for child in self.user_listbox.winfo_children()}
            online_users = set(user_dict.keys())
            
            # Remove users who are offline
            for user, button in current_buttons.items():
                if user not in online_users:
                    button.destroy()
            
            # Add users who are new
            for user in online_users:
                if user not in current_buttons:
                    btn = ctk.CTkButton(self.user_listbox, text=user, command=lambda u=user: self.open_chat_window(u))
                    btn.pack(fill="x", pady=2, padx=2)
        except Exception as e:
            log_event(f"GUI Error in update_user_list_display: {e}")

    def open_chat_window(self, username):
        if username in self.chat_windows and self.chat_windows[username].winfo_exists():
            self.chat_windows[username].lift()
            return
        self.chat_windows[username] = ChatWindow(self, username, self.client_backend)

    def display_received_message(self, sender, message):
        if sender not in self.chat_windows or not self.chat_windows[sender].winfo_exists():
            self.open_chat_window(sender)
        self.chat_windows[sender].add_message(f"{sender}: {message}")

    def on_closing(self):
        if self.client_backend: self.client_backend.stop()
        self.destroy()

class ChatWindow(ctk.CTkToplevel):
    def __init__(self, master, username, client_backend):
        super().__init__(master)
        self.username = username
        self.client_backend = client_backend
        self.in_call = False
        self.title(f"Chat with {username}")
        self.geometry("500x600")
        self.grid_rowconfigure(0, weight=1); self.grid_columnconfigure(0, weight=1)
        self.text_area = ctk.CTkTextbox(self, state="disabled", wrap="word")
        self.text_area.grid(row=0, column=0, columnspan=3, padx=10, pady=10, sticky="nsew")
        self.message_entry = ctk.CTkEntry(self, placeholder_text="Type a message...")
        self.message_entry.grid(row=1, column=0, padx=10, pady=10, sticky="ew")
        self.message_entry.bind("<Return>", self.send_message)
        self.send_button = ctk.CTkButton(self, text="Send", command=self.send_message)
        self.send_button.grid(row=1, column=1, padx=5, pady=10)
        self.call_button = ctk.CTkButton(self, text="📞 Call", command=self.toggle_call, state="normal" if VOICE_CALL_ENABLED else "disabled")
        self.call_button.grid(row=1, column=2, padx=5, pady=10)

    def send_message(self, event=None):
        message = self.message_entry.get()
        if message:
            self.client_backend.send_message(self.username, message)
            self.add_message(f"You: {message}")
            self.message_entry.delete(0, "end")

    def add_message(self, message):
        self.text_area.configure(state="normal")
        self.text_area.insert("end", message + "\n")
        self.text_area.configure(state="disabled")
        self.text_area.see("end")

    def toggle_call(self):
        if not self.in_call:
            self.client_backend.initiate_voice_call(self.username)
        else:
            self.client_backend.end_voice_call_session(self.username)

    def update_call_status(self, in_call):
        self.in_call = in_call
        if in_call:
            self.call_button.configure(text="End Call", fg_color="red")
        else:
            self.call_button.configure(text="📞 Call", fg_color=("#3a7ebf", "#1f538d"))

if __name__ == "__main__":
    ctk.set_appearance_mode("System")
    ctk.set_default_color_theme("blue")
    app = SecuriChatGUI()
    app.mainloop()