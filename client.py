# client.py (Final Working Version)
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
        
        if message.get('checksum') != hashlib.sha256(content.encode('utf-8')).hexdigest():
            log_event(f"Checksum MISMATCH for message from {sender}."); content = f"[CHECKSUM FAILED] {content}"
        else:
            log_event(f"Checksum VERIFIED for message from {sender}")

        if msg_type == "text": self.gui_callback("receive_message", (sender, content))
        elif msg_type == "call_request": self.gui_callback("incoming_call", (sender, int(content)))
        elif msg_type == "call_accepted": self.start_voice_call_session(sender, int(content), is_initiator=True)
        elif msg_type == "call_ended": self.end_voice_call_session(sender, initiated_by_other=True)

    def relay_message(self, inner_message, original_path):
        next_hop_user = inner_message['destination_user']
        if next_hop_user in self.online_users:
            next_hop_info = self.online_users[next_hop_user]
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as relay_socket:
                    relay_socket.connect((next_hop_info['ip'], next_hop_info['port']))
                    
                    # **THE FIX**: The payload for the next hop is already a complete JSON object.
                    # We just need to add the path to it before sending.
                    message_to_forward = inner_message['payload']
                    message_to_forward['path'] = original_path
                    
                    relay_socket.sendall(json.dumps(message_to_forward).encode('utf-8'))
                    log_event(f"Successfully relayed message to {next_hop_user}")
            except Exception as e:
                log_event(f"Failed to relay message to {next_hop_user}: {e}")

    def send_message(self, recipient_user, message_content, msg_type="text"):
        if recipient_user not in self.online_users:
            log_event(f"Cannot send message: User '{recipient_user}' is not online."); return

        available_relays = [u for u in self.online_users if u != recipient_user]
        if not available_relays:
            self.gui_callback("show_error", "Cannot send message: At least 3 users must be online for a relay path."); return

        relay_user = random.choice(available_relays)
        path = [self.username, relay_user, recipient_user]
        log_event(f"Constructing message for {recipient_user} via path: {' -> '.join(path)}")

        final_payload = json.dumps({"sender_user": self.username, "destination_user": recipient_user, "type": msg_type, "content": message_content, "checksum": hashlib.sha256(message_content.encode('utf-8')).hexdigest()}).encode('utf-8')
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

    def initiate_voice_call(self, target_user):
        if not VOICE_CALL_ENABLED or self.voice_call_instance: return
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
        if not VOICE_CALL_ENABLED or not self.voice_call_instance: return
        
        # **THE FIX**: Ensure the correct user is notified, even if initiated by other
        user_to_notify = target_user or self.call_partner
        if not user_to_notify: return # Safety check

        if not initiated_by_other:
            self.send_message(user_to_notify, "ended", msg_type="call_ended")
        
        duration = self.voice_call_instance.get_duration()
        self.voice_call_instance.stop()
        self.voice_call_instance = None
        self.call_partner = None
        
        log_event(f"Voice call with {user_to_notify} ended. Duration: {duration:.2f}s")
        self.gui_callback("call_ended", (user_to_notify, duration))

# --- GUI Application Class ---
class SecuriChatGUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("SecuriChat")
        self.geometry("300x250")
        self.client_backend = None
        self.chat_sessions = {}
        self.current_chat_user = None
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
            messagebox.showerror("Error", "Username and Tracker address are required."); return
        
        try:
            ip, port_str = tracker_addr_str.split(":")
            tracker_addr = (ip, int(port_str))
        except ValueError:
            messagebox.showerror("Error", "Invalid Tracker address format. Use IP:Port."); return

        self.client_backend = SecuriChatClient(username, tracker_addr, self.handle_backend_callback)
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

        ctk.CTkLabel(self.user_frame, text="Online Users", font=ctk.CTkFont(size=16, weight="bold")).pack(pady=10, padx=10)
        self.user_listbox = ctk.CTkScrollableFrame(self.user_frame)
        self.user_listbox.pack(fill="both", expand=True, padx=5, pady=5)

        self.welcome_label = ctk.CTkLabel(self.main_chat_frame, text="Select a user to start chatting.", font=ctk.CTkFont(size=20))
        self.welcome_label.pack(pady=100, padx=20)

    def handle_backend_callback(self, command, data):
        if command == "update_user_list": self.update_user_list_display(data)
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

    def update_user_list_display(self, user_dict):
        if not hasattr(self, 'user_listbox') or not self.user_listbox.winfo_exists():
            self.after(100, lambda: self.update_user_list_display(user_dict)); return
        try:
            current_buttons = {child.cget("text"): child for child in self.user_listbox.winfo_children()}
            online_users = set(user_dict.keys())
            
            for user in online_users:
                if user not in self.chat_sessions: self.chat_sessions[user] = []
            for user, button in current_buttons.items():
                if user not in online_users: button.destroy()
            for user in online_users:
                if user not in current_buttons:
                    btn = ctk.CTkButton(self.user_listbox, text=user, command=lambda u=user: self.switch_chat_view(u))
                    btn.pack(fill="x", pady=2, padx=2)
        except Exception as e:
            log_event(f"GUI Error in update_user_list_display: {e}")

    def switch_chat_view(self, username):
        self.current_chat_user = username
        for widget in self.main_chat_frame.winfo_children(): widget.destroy()

        self.chat_text_area = ctk.CTkTextbox(self.main_chat_frame, state="disabled", wrap="word")
        self.chat_text_area.pack(side="top", fill="both", expand=True, padx=10, pady=(10, 5))
        
        text_color_tuple = self.chat_text_area.cget("text_color")
        text_color = text_color_tuple[0] if ctk.get_appearance_mode() == "Dark" else text_color_tuple[1]

        self.chat_text_area.tag_config("sent", foreground="#C39BD3")
        self.chat_text_area.tag_config("received", foreground=text_color)
        self.chat_text_area.tag_config("system", foreground="gray", justify="center")

        input_frame = ctk.CTkFrame(self.main_chat_frame, fg_color="transparent")
        input_frame.pack(side="bottom", fill="x", expand=False, padx=10, pady=(5, 10))

        self.message_entry = ctk.CTkEntry(input_frame, placeholder_text=f"Message {username}...")
        self.message_entry.pack(side="left", fill="x", expand=True)
        self.message_entry.bind("<Return>", lambda e: self.send_chat_message())

        self.send_button = ctk.CTkButton(input_frame, text="Send", width=70, command=self.send_chat_message)
        self.send_button.pack(side="left", padx=(5, 0))
        
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
            self.client_backend.send_message(self.current_chat_user, message)
            self.add_message_to_session(self.current_chat_user, "sent", f"You: {message}")
            self.message_entry.delete(0, "end")

    def display_received_message(self, sender, message):
        self.add_message_to_session(sender, "received", f"{sender}: {message}")

    def add_message_to_session(self, username, msg_type, text):
        if username not in self.chat_sessions: self.chat_sessions[username] = []
        self.chat_sessions[username].append((msg_type, text))
        if self.current_chat_user == username:
            self.add_message_to_box(text, msg_type)

    def add_message_to_box(self, text, tag):
        if not hasattr(self, 'chat_text_area') or not self.chat_text_area.winfo_exists():
            return
        self.chat_text_area.configure(state="normal")
        self.chat_text_area.insert("end", text + "\n", tag)
        self.chat_text_area.configure(state="disabled")
        self.chat_text_area.see("end")

    def toggle_call(self):
        if self.current_chat_user:
            if self.client_backend.voice_call_instance:
                self.client_backend.end_voice_call_session(self.current_chat_user)
            else:
                self.client_backend.initiate_voice_call(self.current_chat_user)

    def update_call_status(self, username, in_call):
        if self.current_chat_user == username and hasattr(self, 'call_button'):
            if in_call:
                self.call_button.configure(text="End Call", fg_color="red")
            else:
                self.call_button.configure(text="📞 Call", fg_color=("#3a7ebf", "#1f538d"))

    def log_call_in_chat(self, username, duration):
        log_text = f"--- Voice call ended. Duration: {duration:.2f} seconds. ---"
        self.add_message_to_session(username, "system", log_text)

    def on_closing(self):
        if self.client_backend: self.client_backend.stop()
        self.destroy()

if __name__ == "__main__":
    ctk.set_appearance_mode("System")
    ctk.set_default_color_theme("blue")
    app = SecuriChatGUI()
    app.mainloop()