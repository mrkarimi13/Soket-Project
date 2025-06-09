# SecuriChat Project Documentation

This document provides a detailed overview of the implemented mechanisms, log analysis, and test results for the SecuriChat project.

## 1. Implemented Mechanisms

### 1.1. Data Integrity: Checksum (SHA-256)
SecuriChat utilizes SHA-256 checksums to ensure that message content is not altered or corrupted during transmission.

-   **Process:** Before any encryption takes place, the SHA-256 hash of the original message content is calculated. This checksum is then bundled with the message (and itself encrypted as part of the message payload).
-   Upon final decryption at the recipient's end, the recipient's client recalculates the SHA-256 checksum of the received message content.
-   This newly calculated checksum is then compared against the checksum that was originally sent with the message.
-   If the checksums match, it provides a strong guarantee that the message data is intact and has not been tampered with.

-   **Log Evidence:**
    -   Generation: `[2025-06-09 21:30:10] [CRYPTO] Generated SHA-256 checksum for content: 20f65c28671b40937c5bf23acc7c6f37e5a5ec0622e347b57685725df5ba9e50` (from `report.log`)
    -   Verification: `[2025-06-09 21:30:10] [INFO] Checksum VERIFIED for message from c. Data is intact.` (from `report.log`)
    -   Test output also confirms this, for instance, during `test_full_crypto_cycle` and `test_full_p2p_onion_message_passing`, where checksums are generated and verified.

### 1.2. Protocol Usage

SecuriChat leverages several network protocols for its operation:

-   **TCP (Transmission Control Protocol):**
    -   **Tracker Communication:** TCP is used for all communications with the Tracker server. This includes client registration (`REGISTER` command), fetching the list of online users (`GET_USERS` command), and deregistration (`DEREGISTER` command). The use of TCP ensures reliable delivery of these critical commands and responses.
        -   Log Example: `[2025-06-09 21:30:03] [NETWORK] Connecting to tracker at 127.0.0.1:8000 via TCP.`
        -   Log Example: `[2025-06-09 21:30:03] [NETWORK] Sending command 'REGISTER' to tracker.`
    -   **P2P Connection Establishment:** The initial setup for P2P communication, including the relaying of onion-wrapped messages, is done over TCP connections established between clients. This ensures that control messages and encrypted data packets for text messages, file transfers, and call setup are delivered reliably.
        -   Log Example: `[2025-06-09 21:30:03] [P2P] P2P listener started on 0.0.0.0:14531 using TCP.`
        -   Log Example: `[2025-06-09 21:30:10] [NETWORK] Opening TCP connection to first hop 'b' to send a message.`

-   **P2P (Peer-to-Peer):**
    -   **Direct Communication:** P2P is the fundamental model for message exchange in SecuriChat. Once users discover each other via the Tracker, they communicate directly.
    -   **Message Relaying:** In Onion Routing, intermediary clients act as P2P relays, forwarding messages without needing a central server.
    -   **Flexibility:** This architecture enhances privacy and reduces reliance on a single point of failure for message content.

-   **UDP (User Datagram Protocol):**
    -   **Voice Calls:** UDP is employed for transmitting the actual audio data during voice calls. UDP's low-overhead and connectionless nature make it suitable for real-time applications where speed is preferred over guaranteed delivery (occasional packet loss is often acceptable and less disruptive than TCP's retransmission delays).
    -   **Control via TCP:** Importantly, the setup and teardown of voice calls (e.g., 'call_request', 'call_accepted', 'call_ended' messages) are still handled via the secure Onion Routed TCP channel to ensure these control signals are reliably delivered.
        -   Log Example (UDP port info): `[2025-06-09 21:30:28] [NETWORK] Protocol: UDP. My listening port: 14532. Target port: 14524.`
        -   Log Example (Call setup via TCP): `[2025-06-09 21:30:23] [INFO] Initiating voice call with 'c'. Sending 'call_request' via Onion/TCP.`

-   **Onion Routing:**
    -   **Concept:** Onion Routing provides enhanced privacy and security by wrapping messages in multiple layers of encryption. Each layer is encrypted with the public key of an intermediary node (a "hop") in a pre-selected path.
    -   **Path Selection & Message Wrapping:**
        1.  The sending client selects a path of usually two other online users (e.g., Client C -> Relay B -> Recipient A).
        2.  The original message (payload) is first encrypted with Recipient A's public key (this is the innermost layer). This layer also contains information about the final destination.
        3.  This encrypted package is then wrapped in another layer of encryption using Relay B's public key. This outer layer contains information about the next hop (Recipient A).
        4.  If there were more relays, this process would continue, adding more layers.
    -   **Message Unwrapping:**
        1.  The sending client sends the fully wrapped message to the first hop (Relay B).
        2.  Relay B decrypts the outermost layer using its private key. This reveals the next hop (Recipient A) and the still-encrypted inner layer. Relay B cannot read the original message.
        3.  Relay B forwards the inner layer to Recipient A.
        4.  Recipient A decrypts the final layer using its private key to get the original message.
    -   **Log Evidence:**
        -   Path Selection: `[2025-06-09 21:30:10] [CRYPTO] Selected onion path: c -> b -> a`
        -   Innermost Layer Creation: `[2025-06-09 21:30:10] [CRYPTO] Creating innermost layer for recipient 'a'.`
        -   Outer Layer Creation: `[2025-06-09 21:30:10] [CRYPTO] Creating outer layer for relay 'b'.`
        -   Relaying: `[2025-06-09 21:30:10] [P2P] Message is not for me. Relaying to next hop: a. Path: c -> b -> a`
        -   Final Destination: `[2025-06-09 21:30:10] [P2P] Message is for me. Final destination reached. Path: c -> b -> a`

## 2. Analysis of `report.log`

The `report.log` file is crucial for understanding the runtime behavior of SecuriChat clients and for debugging potential issues. It records various events with timestamps, event categories (NETWORK, CRYPTO, P2P, INFO, ERROR), and descriptive messages.

-   **Types of Events Recorded:**
    -   **Client Lifecycle:** Startup, registration with tracker, deregistration, shutdown.
    -   **Tracker Communication:** Attempts to connect, commands sent (REGISTER, GET_USERS, DEREGISTER), and responses received.
    -   **P2P Interactions:** Listener startup, accepted connections, messages sent to hops, messages received, relay decisions, connection closures.
    -   **Cryptographic Operations:** RSA key generation, selection of onion paths, creation of encryption layers (inner, outer), symmetric key generation and encryption, checksum generation, decryption processes, and checksum verification.
    -   **Message Handling:** Sending messages, receiving messages, identifying message type (text, call_request, etc.), processing final messages.
    -   **Voice Call Management:** Initiation of calls, sending/receiving call requests, acceptances, and termination signals, UDP port information, starting/stopping audio streams.
    -   **Errors:** Critical issues preventing normal operation, such as inability to send a message due to insufficient online users for relaying.

-   **Examples of Key Log Entries from `report.log`:**
    -   **User registration with tracker:**
        -   `[2025-06-09 21:30:03] [INFO] Client 'c' starting up...`
        -   `[2025-06-09 21:30:03] [NETWORK] Connecting to tracker at 127.0.0.1:8000 via TCP.`
        -   `[2025-06-09 21:30:03] [NETWORK] Sending command 'REGISTER' to tracker.`
        -   `[2025-06-09 21:30:03] [NETWORK] Received response from tracker: {'status': 'OK', 'message': 'Registered successfully'}`
        -   `[2025-06-09 21:30:03] [INFO] Successfully registered with tracker.`
    -   **Fetching the user list:**
        -   `[2025-06-09 21:30:00] [NETWORK] Sending command 'GET_USERS' to tracker.`
        -   `[2025-06-09 21:30:00] [NETWORK] Received response from tracker: {'b': {'ip': '127.0.0.1', ...}}`
    -   **Onion encryption and decryption steps:**
        -   `[2025-06-09 21:30:10] [CRYPTO] Starting Onion Encryption for a 'text' message to 'a'.`
        -   `[2025-06-09 21:30:10] [CRYPTO] Selected onion path: c -> b -> a`
        -   `[2025-06-09 21:30:10] [CRYPTO] Creating innermost layer for recipient 'a'.`
        -   `[2025-06-09 21:30:10] [CRYPTO] Creating outer layer for relay 'b'.`
        -   `[2025-06-09 21:30:10] [CRYPTO] Starting Onion Decryption Process.`
        -   `[2025-06-09 21:30:10] [CRYPTO] Successfully decrypted one layer of the onion message.`
    -   **Message relay and final delivery:**
        -   `[2025-06-09 21:30:10] [P2P] Message is not for me. Relaying to next hop: a. Path: c -> b -> a`
        -   `[2025-06-09 21:30:10] [P2P] Successfully relayed message to a`
        -   `[2025-06-09 21:30:10] [P2P] Message is for me. Final destination reached. Path: c -> b -> a`
        -   `[2025-06-09 21:30:10] [INFO] Processing final message of type 'text' from 'c'.`
    -   **Voice call setup, connection, and termination:**
        -   `[2025-06-09 21:30:23] [INFO] Initiating voice call with 'c'. Sending 'call_request' via Onion/TCP.`
        -   `[2025-06-09 21:30:28] [INFO] Accepting voice call from 'b'. Sending 'call_accepted' via Onion/TCP.`
        -   `[2025-06-09 21:30:28] [NETWORK] Protocol: UDP. My listening port: 14532. Target port: 14524.`
        -   `[2025-06-09 21:30:28] [INFO] Voice call streams (PyAudio) and UDP socket started successfully.`
        -   `[2025-06-09 21:30:36] [INFO] Ending voice call with 'c'. Sending 'call_ended' message via Onion/TCP.`
        -   `[2025-06-09 21:30:36] [INFO] Voice call with c ended. UDP socket and streams closed. Duration: 7.97s`
    -   **Logged errors:**
        -   `[2025-06-09 21:32:11] [ERROR] Cannot send message: Not enough users online for a relay.`

-   **Utility for Debugging:** These logs provide a step-by-step trace of operations. When a feature isn't working as expected, the logs can help pinpoint where the process failed (e.g., did registration fail? Was the onion path incorrect? Did decryption throw an error?). The timestamps also help in correlating events across different client logs if multiple instances are running.

## 3. Test Results

All unit and integration tests, as described in the project requirements and executed via `python -m unittest test_securichat.py`, **passed successfully**.

-   **Summary of Tests Executed:**
    -   `test_client_registration_and_user_list`: Verifies that a client can successfully register with the tracker and retrieve a list of other online users. This is fundamental for discovering peers.
    -   `test_full_crypto_cycle`: Tests the entire cryptographic pipeline, including RSA key usage, Fernet symmetric key generation, multi-layer onion encryption, decryption through these layers, and final checksum verification. This ensures the core security mechanisms for message confidentiality and integrity are working.
    -   `test_full_p2p_onion_message_passing`: A comprehensive integration test that simulates sending a message from one client to another via one or more relay nodes using the complete Onion Routing P2P protocol. This validates the interaction of networking, P2P logic, and cryptographic modules.
    -   `test_key_generation_and_serialization`: Ensures that RSA public and private keys are generated correctly and can be serialized to the PEM format and deserialized back, which is crucial for storing and transmitting keys.
    -   `test_log_event_writes_to_test_file`: Confirms that the logging system itself is functional and that log events are correctly written to the specified log file (`report.log` in the main application, a test-specific file during tests).

-   **Test Output Summary:**
    The execution of the test suite produced the following summary, indicating all tests passed:
    ```
    Ran 5 tests in 5.788s

    OK
    ```

-   **Confirmation from Detailed Logs:**
    The detailed logs generated during the test execution (as seen in `report.log` excerpts for similar operations) further substantiate the correct functioning of these components. They show the step-by-step operations, such as tracker interactions (registration, user list fetching), the selection of onion paths, the multi-layered encryption process, message relaying between peers, and the final decryption and checksum verification at the recipient. These logs provide transparency into the internal workings of the application during the tests, confirming that each stage of the communication and encryption protocols behaves as expected.
