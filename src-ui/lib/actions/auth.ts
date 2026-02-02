import { get } from 'svelte/store';
import { userStore } from '../stores/user';
import { invoke } from '@tauri-apps/api/core';
import { signalManager } from '../signal_manager';
import { network } from '../network';
import { minePoW, initCrypto } from '../crypto';
import { statusTimeouts, setOnlineStatus, startHeartbeat } from './contacts';
import { broadcastProfile } from './contacts';
import { secureLoad, secureStore, initVault, vaultLoad, vaultSave } from '../secure_storage';
import { attachmentStore } from '../attachment_store';
import type { Chat } from '../types';

let isAuthInProgress = false;
export const resetAuthStatus = () => { isAuthInProgress = false; };

export const initApp = async (password: string) => {
    userStore.update(s => ({ ...s, authError: null }));
    await initCrypto();
    const salt = await secureLoad('entropy_vault_salt');
    const attemptsKey = salt ? `entropy_failed_attempts_${salt.slice(0, 8)}` : 'entropy_failed_attempts_global';

    try {
        await initVault(password);
    } catch (e: any) {
        console.error("Vault init failed:", e);
        const errorMsg = e.message || e.toString();
        if (errorMsg.includes("encryption key") || errorMsg.includes("passphrase")) {
            handleFailedAttempt(attemptsKey);
        } else {
            userStore.update(s => ({ ...s, authError: `System Error: ${errorMsg}` }));
        }
        return;
    }

    let idHash: string | null = null;
    try {
        idHash = await signalManager.init(password, false);
    } catch (e: any) {
        console.error("Signal init failed:", e);
        userStore.update(s => ({ ...s, authError: `Identity Initialization Failed: ${e.message || e}` }));
        return;
    }

    if (idHash) {
        let chats: Record<string, Chat> = {};
        let myAlias: string | null = null;
        let myPfp: string | null = null;
        let sessionToken: string | null = null;

        const saved = await vaultLoad(`entropy_chats_${idHash}`);
        const vaultKey = await signalManager.getLocalEncryptionKey(password);
        if (vaultKey) {
            let storageKey = vaultKey;
            attachmentStore.setEncryptionKey(storageKey);

            if (saved) {
                try {
                    const vault = JSON.parse(saved);
                    const rawChats = vault.chats || vault;

                    for (const h in rawChats) {
                        rawChats[h].isOnline = false;
                        rawChats[h].isTyping = false;
                    }
                    chats = rawChats;
                    myAlias = vault.myAlias || null;
                    myPfp = vault.myPfp || null;
                    sessionToken = vault.sessionToken || null;

                    localStorage.removeItem(attemptsKey);
                    localStorage.removeItem(`entropy_failed_attempts_${idHash}`);
                } catch (e) {
                    userStore.update(s => ({ ...s, authError: "Corrupted vault data." }));
                    return;
                }
            }
        }
        userStore.update(s => ({ ...s, identityHash: idHash, chats, myAlias, myPfp, sessionToken, authError: null }));
        network.connect();
        startHeartbeat();

        const serverUrl = get(userStore).relayUrl;
        try { await signalManager.ensureKeysUploaded(serverUrl); } catch (e) { }
        signalManager.replenishPreKeys(serverUrl).catch(e => console.error("Prekey replenishment failed:", e));
    } else {
        handleFailedAttempt(attemptsKey);
    }
};

const handleFailedAttempt = (key: string) => {
    const attempts = parseInt(localStorage.getItem(key) || "0") + 1;
    localStorage.setItem(key, attempts.toString());

    if (attempts >= 10) {
        invoke('nuclear_reset').catch(() => { });
        const keys = [];
        for (let i = 0; i < localStorage.length; i++) {
            const k = localStorage.key(i);
            if (k && (k.startsWith('entropy_') || k.startsWith('signal_'))) keys.push(k);
        }
        keys.forEach(k => localStorage.removeItem(k));
        userStore.update(s => ({ ...s, authError: "Vault wiped after 10 failed attempts." }));
    } else {
        userStore.update(s => ({ ...s, authError: `Wrong password. Attempts: ${attempts}/10` }));
    }
};

export const createIdentity = async (password: string) => {
    try {
        console.debug("Starting identity creation...");
        await initCrypto();
        console.debug("Crypto initialized.");
        await initVault(password);
        console.debug("Vault initialized.");
    } catch (e: any) {
        console.error("Vault initialization failed:", e);
        throw new Error(`Local vault setup failed: ${e.message || e}`);
    }

    let idHash;
    try {
        console.debug("Initializing Signal manager...");
        idHash = await signalManager.init(password, true);
        console.debug("Signal identity generated:", idHash);
    } catch (e: any) {
        console.error("Identity generation failed:", e);
        throw new Error(`Cryptographic identity generation failed: ${e.message || e}`);
    }

    if (idHash) {
        try {
            let vaultKey = await signalManager.getLocalEncryptionKey(password);
            if (vaultKey) {
                attachmentStore.setEncryptionKey(vaultKey);
            }
            userStore.update(s => ({ ...s, identityHash: idHash }));

            console.debug("Connecting to network...");
            network.connect();
            startHeartbeat();

            console.debug("Uploading keys to server...");
            await signalManager.ensureKeysUploaded(get(userStore).relayUrl);
            console.debug("Keys uploaded.");
        } catch (e: any) {
            console.warn("Post-creation tasks failed (non-critical):", e);
        }
    } else {
        throw new Error("Identity generation returned null.");
    }
};

export const authenticate = async (identityHash: string) => {
    if (isAuthInProgress) return;
    isAuthInProgress = true;

    try {
        const state = get(userStore);
        const serverUrl = state.relayUrl;

        if (state.sessionToken) {
            console.debug("Attempting session-token authentication...");
            userStore.update(s => ({ ...s, connectionStatus: 'connecting' }));
            network.sendJSON({
                type: 'auth',
                payload: {
                    identity_hash: identityHash,
                    session_token: state.sessionToken
                }
            });
        } else {
            console.debug("No session token. Starting PoW mining...");
            userStore.update(s => ({ ...s, connectionStatus: 'mining' }));
            const challengeRes = await fetch(`${serverUrl}/pow/challenge?identity_hash=${identityHash}`);
            const { seed, difficulty } = await challengeRes.json();

            const pow = await minePoW(seed, difficulty, identityHash);

            network.sendJSON({
                type: 'auth',
                payload: { identity_hash: identityHash, seed: pow.seed, nonce: pow.nonce }
            });
        }

        setTimeout(() => {
            const state = get(userStore);
            Object.keys(state.chats).forEach(peerHash => {
                if (!state.chats[peerHash].isGroup) {
                    setOnlineStatus(peerHash, true);
                    broadcastProfile(peerHash);
                }
            });
        }, 1000);
    } catch (e) {
        console.error("Authentication failed:", e);
    } finally {
        isAuthInProgress = false;
    }
};

export const refreshDecoys = async (serverUrl: string) => {
    await signalManager.refreshDecoyPool(serverUrl);
};

export const burnAccount = async (serverUrl: string) => {
    if (confirm("DANGER: This will permanently purge your account from the server AND your local device. This cannot be undone. Are you absolutely sure?")) {
        const success = await signalManager.remoteBurn(serverUrl);
        if (success) {
            window.location.reload();
        } else {
            alert("Forensic burn failed. The server might be unreachable.");
        }
    }
};

export const exportVault = async () => {
    try {
        const { save } = await import('@tauri-apps/plugin-dialog');
        const bytes = await invoke('protocol_export_vault') as number[];
        const uint8 = new Uint8Array(bytes);

        const filePath = await save({
            filters: [{ name: 'Entropy Vault', extensions: ['db'] }],
            defaultPath: 'entropy_backup.db'
        });

        if (filePath) {
            await invoke('protocol_save_vault_to_path', { path: filePath, bytes: Array.from(uint8) });
            alert("Vault exported successfully to: " + filePath);
        }
    } catch (e) {
        console.error("Export failed:", e);
        alert("Export failed: " + e);
    }
};

export const importVault = async () => {
    if (!confirm("DANGER: Importing a vault will overwrite your current local data. This will purge all existing chats on this device. Continue?")) return;

    try {
        const { open } = await import('@tauri-apps/plugin-dialog');
        const file = await open({
            multiple: false,
            filters: [{ name: 'Entropy Vault', extensions: ['db'] }]
        });

        if (file) {
            const path = typeof file === 'string' ? file : (file as any).path;
            const bytes = await invoke('protocol_read_vault_from_path', { path }) as number[];
            await invoke('protocol_import_vault', { bytes });
            alert("Vault imported. The application will now restart.");
            window.location.reload();
        }
    } catch (e) {
        console.error("Import failed:", e);
        alert("Import failed: " + e);
    }
};
