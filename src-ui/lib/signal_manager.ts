
import { invoke } from '@tauri-apps/api/core';
import { sha256, toHex, fromHex } from './crypto';
import { secureStore, secureLoad, vaultLoad, vaultSave } from './secure_storage';

// Replaced complex SignalManager with a simple plaintext manager

export class SignalManager {
    private userIdentity: string = "";

    constructor() {
    }

    async init(password: string): Promise<string | null> {
        // We no longer need password for encryption, but we might use it or just generate an identity if none exists.
        // For plaintext mode, we just need a stable identity hash.

        // Check if we have a stored identity
        let id = await vaultLoad('plaintext_identity');

        // Migration from localStorage if needed
        if (!id) {
            const legacyId = localStorage.getItem('plaintext_identity');
            if (legacyId) {
                console.log("Migrating identity to entropy.db...");
                id = legacyId;
                await vaultSave('plaintext_identity', id);
                localStorage.removeItem('plaintext_identity');
            }
        }

        if (!id) {
            // Generate a random ID
            const random = crypto.randomUUID();
            id = await sha256(random);
            await vaultSave('plaintext_identity', id);

            // Critical verification
            const verify = await vaultLoad('plaintext_identity');
            if (verify !== id) {
                console.error("CRITICAL: Identity save verification failed!");
            } else {
                console.debug("Identity generated and verified:", id);
            }
        }

        this.userIdentity = id!;
        console.log("Initialized Plaintext Protocol. User Hash:", this.userIdentity);
        return this.userIdentity;
    }

    // Kept for compatibility but returns null/empty
    async getLocalEncryptionKey(password: string): Promise<Uint8Array | null> {
        return null;
    }

    // No safety numbers in plaintext
    async getSafetyNumber(recipientHash: string, serverUrl: string): Promise<string> {
        return "Unsecured";
    }

    getUserId(): string {
        return this.userIdentity;
    }

    // No keys to upload
    async ensureKeysUploaded(serverUrl: string, force: boolean = false) {
        // No-op
    }

    // No sessions
    async establishSession(recipientHash: string, serverUrl: string): Promise<string | null> {
        return "plaintext";
    }

    // "Encrypt" just returns the plaintext message in a wrapper
    async encrypt(recipientHash: string, message: string, serverUrl: string, skipIntegrity: boolean = false): Promise<any> {
        return {
            type: 'plaintext',
            body: message,
            sender: this.userIdentity,
            size: message.length
        };
    }

    // "Decrypt" just returns the body
    async decrypt(senderHash: string, ciphertext: any): Promise<any> {
        try {
            if (ciphertext && ciphertext.type === 'plaintext') {
                return JSON.parse(ciphertext.body.trim());
            }
            if (typeof ciphertext === 'string') {
                return JSON.parse(ciphertext.trim());
            }
            if (ciphertext && ciphertext.body) {
                return JSON.parse(ciphertext.body.trim());
            }
        } catch (e) {
            console.error("Plaintext parse error:", e);
        }
        return null;
    }

    async encryptMedia(data: Uint8Array, fileName: string, fileType: string): Promise<{ ciphertext: string, bundle: any }> {
        const hex = toHex(data);
        return {
            ciphertext: hex,
            bundle: {
                type: 'plaintext',
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
