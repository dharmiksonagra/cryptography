🔐 Cryptonix: Advanced Encryption Suite v2.5

This project focuses on understanding the basic concepts of cryptography, different types of cryptographic techniques, and their practical applications in securing digital data.

🚀 Key Features

Multi-Algorithm Support:

AES-256 (Fernet): Industrial-strength symmetric encryption for files and text.

RSA-2048: Asymmetric encryption using Public/Private key pairs for secure data exchange.

DES: Legacy symmetric encryption support for compatibility.

Security Hardening:

Anti-Brute Force: Integrated lockout system that triggers a 60-second cooldown after 3 failed attempts.

Password Enforcement: Strict minimum 8-character requirement for all symmetric keys.

Key Derivation: Uses PBKDF2HMAC with SHA256 and 100,000 iterations for maximum security.

Professional UI:

Dynamic Bold Red Alerts for security violations and system lockouts.

Integrated GUI file selection via Zenity.

🛠️ Installation Prerequisites

Ensure you are running a Linux environment (optimized for Kali Linux) and have Python 3.x installed.

  1.  Clone the Repository Bash

     git clone https://github.com/Omegalharsh/cryptonix.git
     cd cryptonix

   2. Install Dependencies Bash

     pip install cryptography pycryptodome
     sudo apt install zenity

  3.  Grant Permissions Bash

     chmod +x cryptnoix.sh

📖 Usage Guide

Launch the suite using the Bash entry point for the full UI experience: Bash

    ./cryptonix.sh

Encryption Modes

Text Encryption: Encrypt raw strings and view the Base64 output directly in the terminal.

File Encryption: Select files via a GUI window. The tool generates a unique RSA key pair for the file, encrypts the content, and saves it with a .cryptonix extension.

Decryption Modes

AES/DES: Requires the original password used during encryption.

RSA: Requires pasting the multi-line Private Key block including headers.

⚠️ Security Warning

Private Keys: Cryptonix generates temporary RSA keys for file encryption. If you lose the Private Key displayed during encryption, your data cannot be recovered.

Lockout: The system will lock you out for 60 seconds if you enter the wrong key or password 3 time
