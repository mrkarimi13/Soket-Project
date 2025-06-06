# voice_call.py
import pyaudio
import socket
import threading

class VoiceCall:
    def __init__(self, target_ip, target_port, my_port):
        self.target_ip = target_ip
        self.target_port = int(target_port)
        self.my_port = int(my_port)

        self.CHUNK = 1024
        self.FORMAT = pyaudio.paInt16
        self.CHANNELS = 1
        self.RATE = 44100

        self.p = pyaudio.PyAudio()
        self.sending_stream = self.p.open(format=self.FORMAT, channels=self.CHANNELS, rate=self.RATE, input=True, frames_per_buffer=self.CHUNK)
        self.receiving_stream = self.p.open(format=self.FORMAT, channels=self.CHANNELS, rate=self.RATE, output=True, frames_per_buffer=self.CHUNK)

        self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_socket.bind(('0.0.0.0', self.my_port))

        self.is_running = False
        self.receive_thread = threading.Thread(target=self.receive_data, daemon=True)
        self.send_thread = threading.Thread(target=self.send_data, daemon=True)

    def receive_data(self):
        while self.is_running:
            try:
                data, _ = self.udp_socket.recvfrom(self.CHUNK * 2)
                self.receiving_stream.write(data)
            except Exception as e:
                print(f"Error receiving voice data: {e}")
                break

    def send_data(self):
        while self.is_running:
            try:
                data = self.sending_stream.read(self.CHUNK)
                self.udp_socket.sendto(data, (self.target_ip, self.target_port))
            except Exception as e:
                print(f"Error sending voice data: {e}")
                break

    def start(self):
        self.is_running = True
        self.receive_thread.start()
        self.send_thread.start()
        print("Voice call started.")

    def stop(self):
        self.is_running = False
        
        # Wait for threads to finish
        if self.send_thread.is_alive():
            self.send_thread.join(timeout=1)
        if self.receive_thread.is_alive():
            self.receive_thread.join(timeout=1)

        self.sending_stream.stop_stream()
        self.sending_stream.close()
        self.receiving_stream.stop_stream()
        self.receiving_stream.close()
        self.p.terminate()
        self.udp_socket.close()
        print("Voice call stopped.")