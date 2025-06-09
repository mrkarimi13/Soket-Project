# SecuriChat: Secure P2P Messenger

Welcome to SecuriChat, a secure peer-to-peer (P2P) messenger designed with privacy and security at its core. This project, developed for a computer networks course, explores advanced networking concepts like TCP/IP communication, P2P architectures, and multi-layered encryption (Onion Routing) to safeguard your conversations.

## Core Features

*   **Peer-to-Peer (P2P) Communication:** Chat directly with other users without relying on a central server for message relay.
*   **Onion Routing:** Enhance your privacy with multi-layered encryption. Messages are wrapped in several layers of encryption, and each intermediary node in the network can only decrypt one layer, revealing the next hop. This makes it difficult for any single node to know both the origin and the final destination of the message.
*   **End-to-End Encryption:** Messages are encrypted on the sender's device and decrypted only on the recipient's device, ensuring that no one in between (not even the tracker or intermediary nodes) can read your messages.
*   **Reliable Messaging (TCP):** Standard chat messages and critical communication (like connection setup) utilize TCP to ensure messages are delivered reliably and in order.
*   **Data Integrity (Checksums):** Uses SHA-256 checksums to verify that messages haven't been corrupted or tampered with during transmission.
*   **File Sharing:** Securely send and receive files over the encrypted P2P network.
*   **Voice Calls (UDP):** For real-time voice communication, SecuriChat uses UDP, prioritizing speed and low latency. Connection setup for calls still goes through the secure TCP channel.
*   **User-Friendly Interface:** A simple graphical interface built with CustomTkinter for ease of use.
*   **Logging:** Important events are logged to `report.log` for easier debugging and monitoring.

## How It Works

SecuriChat employs a hybrid architecture:

1.  **Tracker Server:**
    *   When a user comes online, their SecuriChat client connects to a central **Tracker** server.
    *   The Tracker acts like a phonebook, maintaining a list of currently online users and their IP addresses and port numbers. It doesn't process or store any message content.
    *   Clients query the Tracker to discover other online users.

2.  **Client-to-Client (P2P) Connection:**
    *   Once a client retrieves the list of online users from the Tracker, it can establish a direct TCP connection with another client for messaging.

3.  **Onion Routing for Enhanced Privacy:**
    *   To send a message from User A to User B with enhanced privacy, User A can choose to route the message through an intermediary online user (User C).
    *   The message is first encrypted for User B, then the result is encrypted again for User C.
    *   When User C receives the packet, they can only decrypt the outer layer, which tells them to forward the remaining encrypted packet to User B.
    *   User C never sees the actual content of the message.
    *   This process uses a combination of asymmetric encryption (RSA) for exchanging one-time symmetric keys (Fernet) which are then used for encrypting the actual message content.

4.  **Error Detection (Checksum):**
    *   Every message includes a **Checksum** (specifically, a SHA-256 hash) calculated from the original message content before any encryption.
    *   The final recipient, after decrypting all layers of encryption, recalculates the checksum of the received content and compares it to the checksum sent with the message.
    *   If the checksums match, it confirms that the message was not altered or corrupted during its journey across the network.

## Getting Started

### Prerequisites

*   Python 3
*   The libraries listed in `requirements.txt`. It's highly recommended to install these in a virtual environment.

    ```bash
    pip install -r requirements.txt
    ```

    The `requirements.txt` file should include:
    ```
    customtkinter
    cryptography
    pyaudio
    ```

    **Important Note for PyAudio:** Installing PyAudio can sometimes be tricky on certain operating systems. If you encounter issues, search online for installation guides specific to your OS. For Windows, the following commands often work:
    ```bash
    pip install pipwin
    pipwin install pyaudio
    ```

### Running the Application

Running SecuriChat involves two main steps:

1.  **Run the Tracker Server:**
    The Tracker maintains the list of online users and their connection information. Open a terminal and run:
    ```bash
    python tracker.py
    ```
    The server will start on `127.0.0.1` at port `8000`, awaiting client connections.

2.  **Run Client Instances:**
    To start chatting, you need to run at least two client instances (or more). For each user, open a separate terminal and run:
    ```bash
    python client.py
    ```
    A graphical window will appear, prompting for a username and the Tracker's address. Enter your desired username. If the Tracker is running on the same machine, the default address `127.0.0.1:8000` is correct.

    **Note for Onion Routing:** To fully test the Onion Routing feature, you need at least three clients running simultaneously. This ensures there's always a third user available to act as an intermediary (relay) for messages.

## Running Tests

Automated tests are provided to ensure the core components of the application, such as the cryptography module and network communications, are functioning correctly. To run these tests, use the following command:

```bash
python -m unittest test_securichat.py
```

This command will execute all tests and display the results in the terminal.

## Project Documentation

This project emphasizes the importance of comprehensive documentation. Detailed explanations of the architecture, design choices, and implementation specifics can be found within the source code comments and any accompanying design documents (if available in the repository). The `report.log` file also provides a runtime log of application events.

This README provides an overview, but for a deeper dive, please consult the code and other documentation artifacts.