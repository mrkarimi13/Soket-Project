import unittest
import os
import time
import threading
import queue


from client import SecuriChatClient, log_event as original_log_event, generate_keys, serialize_public_key, deserialize_public_key
from tracker import main as tracker_main
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet


TRACKER_HOST = '127.0.0.1'
TRACKER_PORT = 8001
TEST_LOG_FILE = "test_report.log"

def test_log_event(message, level="INFO"):
    original_log_event(message, level, log_file_override=TEST_LOG_FILE)

class TestSecuriChat(unittest.TestCase):

    def setUpClass(cls):
        import client
        client.log_event = test_log_event
        cls.tracker_thread = threading.Thread(target=tracker_main, daemon=True)
        import tracker
        tracker.HOST = TRACKER_HOST
        tracker.PORT = TRACKER_PORT
        cls.tracker_thread.start()
        time.sleep(1)

    def setUp(self):
        if os.path.exists(TEST_LOG_FILE):
            os.remove(TEST_LOG_FILE)
        self.clients = []

    def tearDown(self):
        for client in self.clients:
            if client.running:
                client.stop()
        time.sleep(0.2)
        if os.path.exists(TEST_LOG_FILE):
            os.remove(TEST_LOG_FILE)
        for user in ["alice", "bob", "charlie"]:
            history_file = f"history_{user}.json"
            if os.path.exists(history_file):
                os.remove(history_file)

    def _create_client(self, name):
        client = SecuriChatClient(name, (TRACKER_HOST, TRACKER_PORT), queue.Queue())
        self.clients.append(client)
        return client

    def test_log_event_writes_to_test_file(self):
        self.assertFalse(os.path.exists(TEST_LOG_FILE))
        test_log_event("This is a unit test log message.")
        self.assertTrue(os.path.exists(TEST_LOG_FILE))

    def test_key_generation_and_serialization(self):
        private_key, public_key = generate_keys()
        self.assertIsNotNone(private_key)
        pem_public_key = serialize_public_key(public_key)
        deserialized_public_key = deserialize_public_key(pem_public_key)
        self.assertEqual(public_key.public_numbers(), deserialized_public_key.public_numbers())

    def test_full_crypto_cycle(self):
        recipient_private_key, recipient_public_key = generate_keys()
        original_message = b"This is a top secret message."
        symmetric_key = Fernet.generate_key()
        encrypted_message = Fernet(symmetric_key).encrypt(original_message)
        encrypted_symmetric_key = recipient_public_key.encrypt(symmetric_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        decrypted_symmetric_key = recipient_private_key.decrypt(encrypted_symmetric_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        decrypted_message = Fernet(decrypted_symmetric_key).decrypt(encrypted_message)
        self.assertEqual(original_message, decrypted_message)

    # ==================================================================
    # ==                       INTEGRATION TESTS                      ==
    # ==================================================================

    def test_client_registration_and_user_list(self):
        """Integration Test: Ensure clients can register and see each other."""
        alice = self._create_client("alice")
        self.assertTrue(alice.start())
        

        time.sleep(0.5)

        bob = self._create_client("bob")
        self.assertTrue(bob.start())


        time.sleep(1)
        

        alice.update_user_list()

        self.assertIn("bob", alice.online_users, "Alice should see Bob after updating her list.")
        self.assertIn("alice", bob.online_users, "Bob should see Alice immediately after starting.")

    def test_full_p2p_onion_message_passing(self):
        """Integration Test: Test the entire message pipeline."""
        alice = self._create_client("alice")
        bob = self._create_client("bob")
        charlie = self._create_client("charlie")

 
        self.assertTrue(alice.start())
        time.sleep(0.5)
        self.assertTrue(bob.start())
        time.sleep(0.5)
        self.assertTrue(charlie.start())
        time.sleep(0.5)

    
        alice.update_user_list()
        bob.update_user_list()
        charlie.update_user_list()

        
        self.assertIn("bob", alice.online_users)
        self.assertIn("charlie", alice.online_users)

        test_message = f"Hello Bob, this is a test message at {time.time()}"
        alice.send_message("bob", test_message)

        try:
            timeout = time.time() + 5
            message_received = False
            while time.time() < timeout:
                try:
                    command, data = bob.ui_queue.get(timeout=0.1)
                    if command == "receive_message":
                        sender, received_message = data
                        self.assertEqual(sender, "alice")
                        self.assertEqual(received_message, test_message)
                        message_received = True
                        break
                except queue.Empty:
                    continue
            
            self.assertTrue(message_received, "Bob did not receive the 'receive_message' command within the timeout period.")

        except Exception as e:
            self.fail(f"An unexpected error occurred while waiting for the message: {e}")

if __name__ == '__main__':
    unittest.main(verbosity=2)