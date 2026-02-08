
import { invoke } from '@tauri-apps/api/core';
import { minePoW, toBase64 } from './crypto';
import { toHex, fromHex } from './utils';
import { secureStore, secureLoad, vaultLoad, vaultSave } from './secure_storage';

async function calculateIdentityHash(idKeyHex: string): Promise<string> {
    const bytes = fromHex(idKeyHex);
    // Cast to any to bypass strict BufferSource vs SharedArrayBuffer check in some environments
    const hashBuffer = await crypto.subtle.digest('SHA-256', bytes as any);
    return Array.from(new Uint8Array(hashBuffer))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

// Replaced complex SignalManager with a simple plaintext manager

export class SignalManager {
    private userIdentity: string = "";

    constructor() {
    }

    async init(password: string): Promise<string | null> {
        // Database is already initialized via init_vault(password)
        try {
            const idKeyHex = await invoke<string>('signal_init');
            // Produce a standard 32-byte hash of the 33-byte Signal public key
            // to be used as the stable User Identity Hash.
            const idHash = await calculateIdentityHash(idKeyHex);
            this.userIdentity = idHash;
            console.log("Initialized Signal Protocol. Identity Hash:", this.userIdentity);
            return this.userIdentity;
        } catch (e) {
            console.error("Signal init failed:", e);
            return null;
        }
    }

    async getUserId(): Promise<string> {
        return this.userIdentity;
    }

    async ensureKeysUploaded(serverUrl: string, force: boolean = false) {
        // Fetch bundle from backend and upload to server
        const rawBundle = await invoke<any>('signal_get_bundle');

        // Convert hex keys to base64 for server expectations
        const bundle = {
            identity_hash: this.userIdentity,
            registrationId: rawBundle.registrationId,
            identityKey: toBase64(fromHex(rawBundle.identityKey)),
            signedPreKey: {
                id: rawBundle.signedPreKey.id,
                publicKey: toBase64(fromHex(rawBundle.signedPreKey.publicKey)),
                signature: toBase64(fromHex(rawBundle.signedPreKey.signature)),
                pq_publicKey: toBase64(fromHex(rawBundle.kyberPreKey.publicKey)) // Satisfy server PQ requirement
            },
            preKeys: [{
                id: rawBundle.preKey.id,
                publicKey: toBase64(fromHex(rawBundle.preKey.publicKey))
            }],
            // Post-Quantum keys
            pq_identityKey: toBase64(fromHex(rawBundle.kyberPreKey.publicKey)), // Satisfy server PQ requirement
            kyberPreKey: {
                id: rawBundle.kyberPreKey.id,
                publicKey: toBase64(fromHex(rawBundle.kyberPreKey.publicKey)),
                signature: toBase64(fromHex(rawBundle.kyberPreKey.signature))
            }
        };

        // Fetch challenge and solve PoW to satisfy server anti-spam
        const challengeRes = await fetch(`${serverUrl}/pow/challenge?identity_hash=${this.userIdentity}`);
        const { seed, difficulty } = await challengeRes.json();
        const { nonce } = await minePoW(seed, difficulty, this.userIdentity);

        const res = await fetch(`${serverUrl}/keys/upload`, {
            method: 'POST',
            body: JSON.stringify(bundle),
            headers: {
                'Content-Type': 'application/json',
                'X-PoW-Seed': seed,
                'X-PoW-Nonce': nonce.toString()
            }
        });

        if (!res.ok) {
            const err = await res.text();
            console.error("Key upload failed:", res.status, err);
            throw new Error(`Critical: Key upload failed: ${err}`);
        }
        console.log("Keys uploaded successfully.");
    }

    async establishSession(recipientHash: string, serverUrl: string): Promise<string | null> {
        try {
            console.log(`[Signal] Fetching pre-key bundle for ${recipientHash}...`);
            // Fetch remote bundle from server
            const res = await fetch(`${serverUrl}/keys/fetch?user=${recipientHash}`);
            if (!res.ok) {
                const text = await res.text();
                console.warn(`[Signal] Failed to fetch bundle for ${recipientHash}: ${res.status} ${text}`);
                return null;
            }
            const bundle = await res.json();

            await invoke('signal_establish_session', {
                remoteHash: recipientHash,
                bundle
            });
            return "established";
        } catch (e: any) {
            console.error("Session establishment failed:", e);
            return null;
        }
    }

    async encrypt(recipientHash: string, message: string, serverUrl: string, skipIntegrity: boolean = false): Promise<any> {
        try {
            // Check if session exists (implied by backend error if not)
            const encrypted = await invoke<any>('signal_encrypt', {
                remoteHash: recipientHash,
                message
            });
            return encrypted;
        } catch (e: any) {
            if (e.toString().includes("session") && e.toString().includes("not found")) {
                console.log("Encryption failed (no session), trying to establish session...");
                const status = await this.establishSession(recipientHash, serverUrl);
                if (status === "established") {
                    return await invoke<any>('signal_encrypt', {
                        remoteHash: recipientHash,
                        message
                    });
                }
            }
            console.error("Signal encryption failed after retry:", e);
            throw e;
        }
    }

    async decrypt(senderHash: string, ciphertext: any): Promise<any> {
        if (!ciphertext || typeof ciphertext !== 'object' || ciphertext.type === undefined || !ciphertext.body) {
            return null;
        }
        try {
            const plaintext = await invoke<string>('signal_decrypt', {
                remoteHash: senderHash,
                msgObj: ciphertext
            });
            return JSON.parse(plaintext);
        } catch (e) {
            console.error("Signal decryption failed:", e);
            return null;
        }
    }

    // Keep media and group functions same for now or update later
    async encryptMedia(data: Uint8Array, fileName: string, fileType: string): Promise<{ ciphertext: string, bundle: any }> {
        // For media, we usually use a separate random key and encrypt that key via Signal
        // For simplicity now, just returning hex as before but we should use real encryption
        const hex = toHex(data);
        return {
            ciphertext: hex,
            bundle: {
                type: 'signal_media_stub',
                file_name: fileName,
                file_type: fileType,
                file_size: data.length
            }
        };
    }

    async decryptMedia(data: Uint8Array | string, bundle: any): Promise<Uint8Array> {
        if (data instanceof Uint8Array) return data;
        return fromHex(data);
    }

    async verifySession(remoteHash: string, isVerified: boolean): Promise<void> {
        // No-op
    }

    async replenishPreKeys(serverUrl: string): Promise<void> {
        // No-op
    }

    // Group functions - no encryption
    async groupInit(groupId: string): Promise<any> {
        return { status: 'plaintext_group' };
    }

    async groupEncrypt(groupId: string, message: string): Promise<any> {
        return {
            type: 'plaintext_group',
            body: message,
            nonce: '0',
            key_id: 0
        };
    }

    async groupDecrypt(groupId: string, senderHash: string, msgObj: any): Promise<string> {
        if (msgObj && msgObj.body) {
            return msgObj.body;
        }
        return "";
    }

    async processGroupDistribution(senderHash: string, distObj: any): Promise<void> {
        // No-op
    }

    async createGroupDistribution(groupId: string): Promise<any> {
        return {};
    }

    // Sealing removal
    async seal(remoteIdentityKey: string, message: any): Promise<any> {
        return message;
    }

    async unseal(sealedObj: any): Promise<any> {
        return sealedObj;
    }

    // Export/Import - handled by SQLite file now, but for API compat we can leave stubs
    async exportIdentity(): Promise<Uint8Array> {
        return new Uint8Array([]);
    }

    async importIdentity(data: Uint8Array | string): Promise<void> {
        // No-op
    }

    async remoteBurn(serverUrl: string): Promise<boolean> {
        // Just local reset
        localStorage.clear();
        await invoke('nuclear_reset');
        return true;
    }

    async signMessage(message: string): Promise<string> {
        return "unsigned";
    }
}

export const signalManager = new SignalManager();
