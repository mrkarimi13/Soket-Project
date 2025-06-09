import pyaudio
import socket
import threading
import time

class VoiceCall:
    def __init__(self, target_ip, target_port, my_port):
        self.target_ip = target_ip
        self.target_port = int(target_port)
        self.my_port = int(my_port)

        self.CHUNK = 1024
        self.FORMAT = pyaudio.paInt16
        self.CHANNELS = 1
        self.RATE = 44100

        self.p = None
        self.sending_stream = None
        self.receiving_stream = None
        self.udp_socket = None

        self.is_running = False
        self.receive_thread = threading.Thread(target=self.receive_data, daemon=True)
        self.send_thread = threading.Thread(target=self.send_data, daemon=True)
        
        self.start_time = None
        self.end_time = None

    def start(self):
        if self.is_running:
            return
        
        self.is_running = True
        self.start_time = time.time()
        
        try:
            self.p = pyaudio.PyAudio()
            self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.udp_socket.bind(('0.0.0.0', self.my_port))
            
            self.sending_stream = self.p.open(format=self.FORMAT, channels=self.CHANNELS, rate=self.RATE, input=True, frames_per_buffer=self.CHUNK)
            self.receiving_stream = self.p.open(format=self.FORMAT, channels=self.CHANNELS, rate=self.RATE, output=True, frames_per_buffer=self.CHUNK)
            
            self.receive_thread.start()
            self.send_thread.start()
            print("Voice call started successfully.")
            return True
        except Exception as e:
            print(f"Error starting voice call: {e}")
            self.stop() # Clean up if start fails
            return False

    def receive_data(self):
        while self.is_running:
            try:
                data, _ = self.udp_socket.recvfrom(self.CHUNK * 2)
                if self.is_running and self.receiving_stream:
                    self.receiving_stream.write(data)
            except (socket.error, OSError):
                # This is expected when the socket is closed
                break
            except Exception as e:
                print(f"Error receiving voice data: {e}")
                break

    def send_data(self):
        while self.is_running:
            try:
                data = self.sending_stream.read(self.CHUNK, exception_on_overflow=False)
                if self.is_running and self.udp_socket:
                    self.udp_socket.sendto(data, (self.target_ip, self.target_port))
            except (IOError, AttributeError):
                # This is expected when the stream is closed
                break
            except Exception as e:
                print(f"Error sending voice data: {e}")
                break

    def stop(self):
        if not self.is_running:
            return
            
        self.is_running = False
        self.end_time = time.time()

        # Close socket first to unblock threads
        if self.udp_socket:
            self.udp_socket.close()
            self.udp_socket = None

        # Wait for threads to finish
        if self.send_thread.is_alive():
            self.send_thread.join(timeout=0.5)
        if self.receive_thread.is_alive():
            self.receive_thread.join(timeout=0.5)

        # Close PyAudio streams
        if self.sending_stream:
            self.sending_stream.stop_stream()
            self.sending_stream.close()
            self.sending_stream = None
        if self.receiving_stream:
            self.receiving_stream.stop_stream()
            self.receiving_stream.close()
            self.receiving_stream = None
        
        if self.p:
            self.p.terminate()
            self.p = None
            
        print("Voice call stopped and resources released.")

    def get_duration(self):
        if self.start_time and self.end_time:
            return self.end_time - self.start_time
        return 0