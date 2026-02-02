
import { invoke } from '@tauri-apps/api/core';

import { SignalStore } from './signal_store';
import { minePoW, deriveVaultKey, sha256, fromBase64 } from './crypto';
import { secureLoad, secureStore } from './secure_storage';


function buf2hex(buffer: ArrayBuffer): string {
    return Array.from(new Uint8Array(buffer))
        .map(x => x.toString(16).padStart(2, '0'))
        .join('');
}

function hex2buf(hex: string): ArrayBuffer {
    const bytes = new Uint8Array(Math.ceil(hex.length / 2));
    for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return bytes.buffer;
}

export class SignalManager {
    private store: SignalStore;
    private userIdentity: string = "";
    private initialRegistrationId: number = 0;
    private operationLock: Promise<any> = Promise.resolve();
    private _decoyPool: Set<string> = new Set();

    constructor() {
        this.store = new SignalStore();
    }

    private async lock<T>(fn: () => Promise<T>): Promise<T> {
        const result = this.operationLock.then(fn);
        this.operationLock = result.catch(() => { });
        return result;
    }

    private async getDecoyHashes(serverUrl: string): Promise<string[]> {
        if (this._decoyPool.size < 5) {
            await this.refreshDecoyPool(serverUrl);
        }

        const candidates = Array.from(this._decoyPool);
        return candidates.sort(() => 0.5 - Math.random()).slice(0, 3);
    }

    async refreshDecoyPool(serverUrl: string): Promise<void> {
        try {
            const challengeRes = await fetch(`${serverUrl}/pow/challenge?type=decoy`);
            if (!challengeRes.ok) return;
            const { seed, difficulty } = await challengeRes.json();
            const pow = await minePoW(seed, difficulty);

            const res = await fetch(`${serverUrl}/keys/random?count=15`, {
                headers: {
                    'X-PoW-Seed': seed,
                    'X-PoW-Nonce': pow.nonce.toString()
                }
            });

            if (res.ok) {
                const { hashes } = await res.json();
                if (hashes) {
                    hashes.forEach((h: string) => {
                        if (h !== this.userIdentity) this._decoyPool.add(h);
                    });
                }
            }
        } catch (e) { }
    }

    async init(password: string, autoCreate: boolean = true): Promise<string | null> {
        return this.lock(async () => {

            const identityExists = !(await this.store.isBlankSlate());
            let salt = await secureLoad('entropy_vault_salt');

            if (!salt) {
                if (identityExists && !autoCreate) {
                    console.error("SignalManager: Identity exists but salt is missing!");
                    throw new Error("Secure identity found, but the encryption salt is missing from your system keyring. Please ensure your OS keyring is unlocked.");
                }

                if (identityExists && autoCreate) {
                    console.warn("SignalManager: stale identity found without salt. Wiping for fresh start.");
                    await this.store.deleteAllData();
                }

                console.debug("SignalManager: Generating new vault salt.");
                salt = crypto.randomUUID();
                await secureStore('entropy_vault_salt', salt);
            }

            const vaultKey = await deriveVaultKey(password, salt);
            this.store.setEncryptionKey(vaultKey);


            let identityBundle: any;
            try {
                identityBundle = await invoke('protocol_init');
            } catch (e) {
                console.error("SignalManager: Protocol Init Invoke Failed. This usually means the vault wasn't correctly initialized in Rust.", e);
                throw e; // Throw instead of returning null to allow caller to handle it
            }


            this.initialRegistrationId = identityBundle.registration_id;


            const pubKeyB64 = identityBundle.identity_key;

            if (!pubKeyB64) {
                console.error("SignalManager: Identity Key is missing from bundle!", identityBundle);
                throw new Error("Identity Key missing");
            }



            const cleanKey = pubKeyB64.replace(/[\n\r\s]/g, '');
            let binaryKey: Uint8Array;
            try {
                binaryKey = fromBase64(cleanKey);
            } catch (e) {
                console.error("SignalManager: Failed to decode Identity Key:", cleanKey, e);

                const standardKey = cleanKey.replace(/-/g, '+').replace(/_/g, '/');
                binaryKey = fromBase64(standardKey);
            }

            this.userIdentity = await sha256(binaryKey);

            console.debug("Initialized Rust Protocol. User Hash:", this.userIdentity);


            (this as any)._cachedBundle = identityBundle;

            return this.userIdentity;
        });
    }

    async getLocalEncryptionKey(password: string): Promise<Uint8Array | null> {
        const salt = await secureLoad('entropy_vault_salt');
        if (!salt) return null;
        return await deriveVaultKey(password, salt);
    }

    async getSafetyNumber(recipientHash: string, serverUrl: string): Promise<string> {
        return this.lock(async () => {
            const response = await fetch(`${serverUrl}/keys/fetch?user=${recipientHash}`);
            if (!response.ok) return "Unknown";
            const bundle = await response.json();
            const remoteIk = bundle.identityKey;

            const rustBundle = (this as any)._cachedBundle;
            if (!rustBundle) return "Error";
            const myIk = rustBundle.identity_key;

            return await invoke('protocol_get_safety_number', {
                meIk: myIk,
                peerIk: remoteIk
            });
        });
    }

    async getPublicIdentityKey(): Promise<string> {
        const rustBundle = (this as any)._cachedBundle;
        if (rustBundle) return rustBundle.identity_key;

        const bundle: any = await invoke('protocol_init');
        (this as any)._cachedBundle = bundle;
        return bundle.identity_key;
    }

    getUserId(): string {
        return this.userIdentity;
    }

    async ensureKeysUploaded(serverUrl: string, force: boolean = false) {
        if (!force && localStorage.getItem('signal_keys_uploaded') === 'true') return;

        console.debug("Preparing keys for upload form Rust backend...");


        const rustBundle = (this as any)._cachedBundle;
        if (!rustBundle) throw new Error("Rust identity bundle not found. Init first.");

        const bundle: any = {
            identity_hash: this.userIdentity,
            registrationId: rustBundle.registration_id,
            identityKey: rustBundle.identity_key,
            pq_identityKey: rustBundle.pq_identity_key,
            signedPreKey: {
                keyId: rustBundle.signed_pre_key.key_id,
                publicKey: rustBundle.signed_pre_key.public_key,
                pq_publicKey: rustBundle.signed_pre_key.pq_public_key,
                signature: rustBundle.signed_pre_key.signature
            },
            preKeys: rustBundle.pre_keys.slice(-100).map((k: any) => ({
                keyId: k.key_id,
                publicKey: k.public_key
            }))
        };



        const signData = JSON.stringify({
            identityKey: bundle.identityKey,
            pq_identityKey: bundle.pq_identityKey,
            signedPreKey: bundle.signedPreKey,
            preKeys: bundle.preKeys
        });
        bundle.bundle_signature = await invoke('protocol_sign', { message: signData });


        const challengeRes = await fetch(`${serverUrl}/pow/challenge?identity_hash=${this.userIdentity}`);
        const { seed, difficulty } = await challengeRes.json();


        const pow = await minePoW(seed, difficulty, this.userIdentity);

        const response = await fetch(`${serverUrl}/keys/upload`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-PoW-Seed': pow.seed,
                'X-PoW-Nonce': pow.nonce.toString()
            },
            body: JSON.stringify(bundle)
        });

        if (!response.ok) {
            throw new Error(`Failed to upload keys: ${await response.text()}`);
        }

        console.debug("Keys uploaded successfully.");
        localStorage.setItem('signal_keys_uploaded', 'true');
    }

    async establishSession(recipientHash: string, serverUrl: string, useDecoys: boolean = false): Promise<{ ik: string, pq_ik: string } | null> {
        let bundle: any = null;
        if (!(this as any)._knownSessions || !(this as any)._knownSessions.has(recipientHash)) {
            if (!/^[0-9a-fA-F]+$/.test(recipientHash)) return null;

            let fetchUrl = `${serverUrl}/keys/fetch?user=${recipientHash}`;
            if (useDecoys) {
                const decoys = await this.getDecoyHashes(serverUrl);
                if (decoys.length > 0) {
                    fetchUrl = `${serverUrl}/keys/fetch?user=${[recipientHash, ...decoys].join(',')}`;
                }
            }

            const response = await fetch(fetchUrl);
            if (!response.ok) return null;
            const data = await response.json();
            bundle = data[recipientHash] || data;

            try {
                await invoke('protocol_establish_session', { remoteHash: recipientHash, bundle });
                if (!(this as any)._knownSessions) (this as any)._knownSessions = new Set();
                (this as any)._knownSessions.add(recipientHash);
            } catch (e) {
                console.error("Rust Session Establish Error:", e);
                return null;
            }
        } else {
            const response = await fetch(`${serverUrl}/keys/fetch?user=${recipientHash}`);
            if (response.ok) bundle = await response.json();
        }

        if (!bundle) return null;
        return {
            ik: bundle.identityKey,
            pq_ik: bundle.pq_identityKey || bundle.pq_identity_key
        };
    }

    async encrypt(recipientHash: string, message: string, serverUrl: string, skipIntegrity: boolean = false): Promise<any> {
        return this.lock(async () => {
            const remoteKeys = await this.establishSession(recipientHash, serverUrl);

            const ciphertext: any = await invoke('protocol_encrypt', {
                remoteHash: recipientHash,
                plaintext: message
            });

            if (remoteKeys) {
                try {
                    return await this.seal(remoteKeys.ik, remoteKeys.pq_ik, ciphertext);
                } catch (e) {
                    console.warn("Sealing failed, falling back to unsealed message", e);
                }
            }

            return ciphertext;
        });
    }

    async decrypt(senderHash: string, ciphertext: any): Promise<any> {
        return this.lock(async () => {
            try {
                const plaintextStr = await invoke('protocol_decrypt', {
                    remoteHash: senderHash,
                    msgObj: ciphertext
                }) as string;
                return JSON.parse(plaintextStr);
            } catch (e) {
                console.error("Rust Decrypt Error:", e);
                throw e;
            }
        });
    }

    async encryptMedia(data: Uint8Array, fileName: string, fileType: string): Promise<{ ciphertext: string, bundle: any }> {
        return await invoke('protocol_encrypt_media', { data: Array.from(data), fileName, fileType });
    }

    async decryptMedia(hexData: string, bundle: any): Promise<Uint8Array> {
        const data = await invoke('protocol_decrypt_media', { hexData, bundle }) as number[];
        return new Uint8Array(data);
    }

    async encryptMediaChunk(keyB64: string, nonceB64: string, chunkIndex: number, data: Uint8Array): Promise<Uint8Array> {
        const res = await invoke('protocol_encrypt_media_chunk', { keyB64, nonceB64, chunkIndex, data: Array.from(data) }) as number[];
        return new Uint8Array(res);
    }

    async decryptMediaChunk(keyB64: string, nonceB64: string, chunkIndex: number, ciphertext: Uint8Array): Promise<Uint8Array> {
        const res = await invoke('protocol_decrypt_media_chunk', { keyB64, nonceB64, chunkIndex, ciphertext: Array.from(ciphertext) }) as number[];
        return new Uint8Array(res);
    }

    async verifySession(remoteHash: string, isVerified: boolean): Promise<void> {
        await invoke('protocol_verify_session', { remoteHash, isVerified });
    }

    async replenishPreKeys(serverUrl: string): Promise<void> {
        await invoke('protocol_replenish_pre_keys', { count: 50 });
        // Refresh the cached bundle from Rust DB so ensureKeysUploaded uses the new pre-keys.
        const bundle: any = await invoke('protocol_init');
        (this as any)._cachedBundle = bundle;

        await this.ensureKeysUploaded(serverUrl, true);
    }

    async groupInit(groupId: string): Promise<any> {
        return await invoke('protocol_group_init', { groupId });
    }

    async groupEncrypt(groupId: string, message: string): Promise<any> {
        return await invoke('protocol_group_encrypt', { groupId, plaintext: message });
    }

    async groupDecrypt(groupId: string, senderHash: string, msgObj: any): Promise<string> {
        return await invoke('protocol_group_decrypt', { groupId, senderHash, msgObj });
    }

    async processGroupDistribution(senderHash: string, distObj: any): Promise<void> {
        await invoke('protocol_process_group_distribution', { senderHash, distObj });
    }

    async createGroupDistribution(groupId: string): Promise<any> {
        return await invoke('protocol_create_group_distribution', { groupId });
    }

    async seal(remoteIdentityKey: string, remotePqIdentityKey: string, message: any): Promise<any> {
        return await invoke('protocol_encrypt_sealed', {
            remotePublicIdentityKey: remoteIdentityKey,
            remotePqPublicIdentityKey: remotePqIdentityKey,
            messageBody: message
        });
    }

    async unseal(sealedObj: any): Promise<any> {
        return await invoke('protocol_decrypt_sealed', { sealedObj });
    }

    async exportIdentity(): Promise<Uint8Array> {
        return this.lock(async () => {
            const salt = await secureLoad('entropy_vault_salt');
            const vaultBinary: number[] = await invoke('protocol_export_vault');

            // Still include these for convenience/portability
            const vaultData = await invoke('dump_vault');

            const payload = {
                v: 2, // Upgraded version
                ts: Date.now(),
                s: salt,
                db: vaultBinary, // The actual encrypted database bytes
                vlt: vaultData,
                cfg: { ...localStorage }
            };

            const json = JSON.stringify(payload);
            const encoded = new TextEncoder().encode(json);

            const header = new TextEncoder().encode("ENTROPY_VAULT_V2\n");
            const combined = new Uint8Array(header.length + encoded.length);
            combined.set(header);
            combined.set(encoded, header.length);

            return combined;
        });
    }

    async importIdentity(data: Uint8Array | string): Promise<void> {
        return this.lock(async () => {
            let json = "";
            const headerV2 = "ENTROPY_VAULT_V2";

            if (typeof data !== 'string') {
                const decoded = new TextDecoder().decode(data);
                const start = decoded.indexOf('{');
                if (start === -1) throw new Error("Invalid Entropy Vault file: Missing JSON");
                json = decoded.substring(start);
            } else {
                json = data;
            }

            if (!json) throw new Error("Empty vault data");
            const finalJson = json.toString();
            const payload = JSON.parse(finalJson.substring(finalJson.indexOf('{')).trim());
            const salt = payload.s || payload.salt;
            const dbBinary = payload.db; // The raw binary database (V2+)
            const settings = payload.cfg || payload.settings;

            if (salt) await secureStore('entropy_vault_salt', salt);

            if (dbBinary) {
                await invoke('protocol_import_vault', { bytes: dbBinary });
            } else {
                throw new Error("Invalid vault backup: Missing binary database (Legacy V1 backups are no longer supported)");
            }

            if (settings) {
                for (const k in settings) {
                    localStorage.setItem(k, settings[k]);
                }
            }
        });
    }

    async remoteBurn(serverUrl: string): Promise<boolean> {
        return this.lock(async () => {
            console.warn("INITIATING FORENSIC REMOTE BURN...");
            const rustBundle = (this as any)._cachedBundle;
            if (!rustBundle) return false;

            const challengeRes = await fetch(`${serverUrl}/pow/challenge?identity_hash=${this.userIdentity}`);
            const { seed, difficulty } = await challengeRes.json();
            const pow = await minePoW(seed, 5, this.userIdentity);

            const signature = await this.signMessage("BURN:" + this.userIdentity);

            const response = await fetch(`${serverUrl}/account/burn`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-PoW-Seed': pow.seed,
                    'X-PoW-Nonce': pow.nonce.toString()
                },
                body: JSON.stringify({
                    identity_hash: this.userIdentity,
                    identityKey: rustBundle.identity_key,
                    signature: signature
                })
            });

            if (response.ok) {
                console.log("Account successfully purged from server.");
                await invoke('nuclear_reset');
                localStorage.clear();
                return true;
            }
            return false;
        });
    }

    async signMessage(message: string): Promise<string> {
        return await invoke('protocol_sign', { message });
    }
}

export const signalManager = new SignalManager();
