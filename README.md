# 🌌 Entropy Desktop

[![Status](https://img.shields.io/badge/status-active-green?style=for-the-badge&logo=statuspage)](https://github.com/Moyzy/entropy)
[![License](https://img.shields.io/badge/license-AGPLv3-blue?style=for-the-badge&logo=gnu)](./LICENSE)
[![Protocol](https://img.shields.io/badge/Protocol-X3DH%2BPQ-blueviolet?style=for-the-badge)](./SPECS.md)

**Entropy Desktop** is a sovereign, decentralized messaging client built for the future. It leverages a "Zero-Knowledge" routing architecture where privacy isn't just a policy—it's a mathematical guarantee.

---

## ✨ What Entropy Desktop Does

- **� End-to-End Encrypted Messaging**: Send text, files, and media with complete privacy. Messages are encrypted using a hybrid X3DH+Kyber1024 protocol before leaving your device.
- **👥 Private Group Chats**: Create encrypted group conversations with perfect forward secrecy. Each participant gets individually encrypted envelopes.
- **📎 Secure File Attachments**: Share images, videos, and files up to 100MB. All attachments are encrypted locally and split into chunks for efficient P2P delivery.
- **🎭 Anonymous Identity System**: No phone numbers, no email addresses. Your identity is just a cryptographic hash that only you control.
- **📛 Human-Readable Nicknames**: Register optional nicknames (e.g., `@alice`) for easier discovery while maintaining cryptographic verification.
- **📬 Offline Message Queue**: If you're offline, messages are stored encrypted on the relay server and delivered when you reconnect (with automatic deletion after retrieval).
- **🔔 Desktop Notifications**: Get notified of new messages with privacy-preserving desktop notifications (content is kept minimal).
- **🗑️ Forensic Burn**: Instantly wipe your entire account from both your device and all relay servers with one click.
- **💾 Vault Export/Import**: Backup your encrypted conversation history and transfer it between devices.
- **🌐 Multi-Relay Support**: Connect to any compatible Entropy relay server or run your own.
- **🕵️ Traffic Normalization**: Client-side padding and dummy messages hide metadata like message size and timing from network observers.

### Cryptographic Features

- **X3DH + Kyber1024**: Post-quantum resistant key agreement combining classical elliptic curves with lattice-based cryptography.
- **Double Ratchet**: Signal-like message key rotation for forward secrecy and break-in recovery.
- **Continuity Lock**: Hash-chain verification prevents server-side message deletion or reordering attacks.
- **Sealed Sender**: Optional mode where the relay server cannot see who sent a message, only who receives it.

---

## 🛠️ Technical Architecture

Entropy Desktop is a native cross-platform desktop application with a security-first architecture:

### Technology Stack
- **Backend**: Rust (Tauri v2) - Handles all cryptography, vault management, and network I/O. Memory-safe and fast.
- **Frontend**: Svelte 5 + TypeScript - Reactive UI with type-safe message handling and state management.
- **Storage**: SQLCipher - All conversation data, keys, and metadata are encrypted at rest with AES-256-CBC.
- **Crypto Library**: `libsodium` (via sodium-native bindings) + custom Rust implementations for Ed25519, X25519, and Kyber1024.
- **Network**: WebSockets over TLS for real-time messaging. Optional SOCKS5 proxy support for Tor/I2P routing.

### Why Rust?
We explicitly chose to build the core backend logic in Rust rather than JavaScript/Node.js to provide a hardened security layer.
- **Process Isolation**: In a standard web application, a "Cross-Site Scripting" (XSS) compromise allows an attacker to read *any* data in the application's memory, including private keys. By moving sensitive logic to Rust, we create a hardware-enforced boundary. Even if the frontend (UI) is compromised by a malicious server response, it physically cannot read the memory of the backend where your keys live, because the Operating System isolates these two processes.
- **Immutable Logic**: Unlike interpreted JavaScript which can be modified at runtime (e.g., via "Prototype Pollution"), the Rust backend is compiled machine code. A malicious server cannot inject new code to alter the encryption protocols or exfiltrate data.
- **Memory Safety**: Rust's ownership model guarantees memory safety at compile-time, eliminating entire classes of vulnerabilities like buffer overflows that could otherwise allow an attacker to bypass these isolation protections.

### Security Architecture
- **Vault Encryption**: Your master password never leaves the device. It's used to derive a database encryption key via PBKDF2 with a hardware-bound salt stored in the system keyring.
- **Key Isolation**: Private keys are generated and stored exclusively in the Rust backend. The TypeScript frontend never sees raw private key material.
- **Rate Limiting**: Client enforces Proof-of-Work challenges for expensive operations to prevent spam and abuse.
- **Minimal Attack Surface**: All privileged operations (file I/O, system keyring access, signing) happen in the auditable Rust layer.

---

## 🚀 Quick Start

### 1. Prerequisites
- **Node.js** 20+
- **Rust** 1.75+
- **System dependencies** (GTK3, WebKit2Gtk, etc. - see [Docs](./CONTRIBUTING.md))

### 2. Setup
```bash
git clone https://github.com/entropy-messenger/Entropy-Desktop.git
cd Entropy-Desktop/DesktopApp
npm install
```

### 3. Launch Development Mode
```bash
npm run tauri dev
```

---

## ⚙️ Configuration (Environment Variables)

Entropy uses Vite environment variables for build-time configuration. Create a `.env` file in the `DesktopApp` directory:

```ini
# The URL of the Entropy Relay server
VITE_RELAY_URL= ...

- **Development**: Defaults to `http://localhost:8080`.
- **Production**: Set `VITE_RELAY_URL` before running `npm run tauri build` to bake in your custom relay.

---

## 🏗️ Building for Production

To create a production-ready bundle optimized for your platform:

```bash
npm run tauri build
```
The optimized binary will be located in `src-tauri/target/release/bundle`.

---

## 🧪 Verification

Security is a primary goal. You can audit the protocol and implementation via our test suites:

```bash
# Verify Cryptographic Protocol (Rust)
cd src-tauri && cargo test

# Verify Frontend Logic & UI (Vitest)
npm run test
```

---

## 📚 Documentation

- **[Technical Specifications](./SPECS.md)**: Deep dive into the cryptographic architecture.
- **[Network API](./API.md)**: Details on relay node interaction.
- **[Contributing](./CONTRIBUTING.md)**: How to help develop Entropy.

---

## 📄 License

Entropy is free and open-source software licensed under the **AGPLv3**.

---

*“Privacy is not a luxury. It is a fundamental human right.”*
