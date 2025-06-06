# test_project.py
import unittest
import hashlib
import json
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# Helper functions from client.py for testing
def generate_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

def deserialize_public_key(pem_data):
    return serialization.load_pem_public_key(pem_data.encode('utf-8'))


class TestCryptoFunctions(unittest.TestCase):

    def setUp(self):
        """Set up for each test."""
        self.private_key, self.public_key = generate_keys()
        self.message = "This is a secret test message for SecuriChat."
        self.message_bytes = self.message.encode('utf-8')

    def test_key_generation_and_serialization(self):
        """Test if keys are generated and can be serialized/deserialized."""
        pem_public_key = serialize_public_key(self.public_key)
        self.assertIn("-----BEGIN PUBLIC KEY-----", pem_public_key)
        
        deserialized_pk = deserialize_public_key(pem_public_key)
        self.assertIsNotNone(deserialized_pk)
        self.assertEqual(self.public_key.public_numbers(), deserialized_pk.public_numbers())

    def test_encryption_decryption(self):
        """Test a single layer of RSA OAEP encryption and decryption."""
        # Encrypt with public key
        ciphertext = self.public_key.encrypt(
            self.message_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        self.assertNotEqual(self.message_bytes, ciphertext)

        # Decrypt with private key
        plaintext = self.private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        self.assertEqual(self.message_bytes, plaintext)
        self.assertEqual(self.message, plaintext.decode('utf-8'))

    def test_checksum(self):
        """Test SHA-256 checksum generation."""
        expected_checksum = hashlib.sha256(self.message_bytes).hexdigest()
        
        payload = {
            "content": self.message,
            "checksum": expected_checksum
        }
        
        # Simulate receiver side
        received_content = payload['content']
        received_checksum = payload['checksum']
        calculated_checksum = hashlib.sha256(received_content.encode('utf-8')).hexdigest()
        
        self.assertEqual(received_checksum, calculated_checksum)

    def test_onion_routing_simulation(self):
        """Simulate the layering of encryption for onion routing."""
        # Setup: Sender, Relay, Recipient
        sender_priv, sender_pub = generate_keys()
        relay_priv, relay_pub = generate_keys()
        recipient_priv, recipient_pub = generate_keys()

        # 1. Create final payload
        final_payload = {
            "sender": "Alice",
            "content": self.message
        }
        final_payload_bytes = json.dumps(final_payload).encode('utf-8')

        # 2. Encrypt for Recipient
        encrypted_for_recipient = recipient_pub.encrypt(final_payload_bytes, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

        # 3. Create relay payload and encrypt for Relay
        relay_payload = {
            "next_hop": "Recipient",
            "payload": encrypted_for_recipient
        }
        relay_payload_bytes = json.dumps(relay_payload, cls=BytesEncoder).encode('utf-8')
        encrypted_for_relay = relay_pub.encrypt(relay_payload_bytes, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

        # --- SIMULATE UNWRAPPING ---
        
        # 4. Relay receives and decrypts its layer
        decrypted_by_relay_bytes = relay_priv.decrypt(encrypted_for_relay, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        decrypted_by_relay = json.loads(decrypted_by_relay_bytes.decode('utf-8'), object_hook=bytes_decoder)
        
        self.assertEqual(decrypted_by_relay['next_hop'], "Recipient")
        
        # 5. Recipient receives and decrypts the final layer
        payload_for_recipient = decrypted_by_relay['payload']
        final_decrypted_bytes = recipient_priv.decrypt(payload_for_recipient, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        final_decrypted_payload = json.loads(final_decrypted_bytes.decode('utf-8'))

        self.assertEqual(final_decrypted_payload['content'], self.message)
        print("\nOnion routing simulation successful.")


# Custom JSON encoder/decoder to handle bytes for the test
class BytesEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, bytes):
            return {'__bytes__': True, 'data': obj.decode('latin1')}
        return json.JSONEncoder.default(self, obj)

def bytes_decoder(obj):
    if '__bytes__' in obj:
        return obj['data'].encode('latin1')
    return obj


if __name__ == '__main__':
    unittest.main()