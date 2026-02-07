
import { get } from 'svelte/store';
import { userStore } from '../stores/user';
import { invoke } from '@tauri-apps/api/core';
import { signalManager } from '../signal_manager';
import { network } from '../network';
import { minePoW, initCrypto } from '../crypto';
import { statusTimeouts, setOnlineStatus, startHeartbeat, broadcastProfile } from './contacts';
import { initVault, vaultLoad, vaultSave } from '../secure_storage';
import type { Chat } from '../types';

let isAuthInProgress = false;

export const initApp = async (password: string) => {
    userStore.update(s => ({ ...s, authError: null }));
    await initCrypto();

    // No salt or secureLoad used. Straight to vault init.
    try {
        await initVault(password);
    } catch (e) {
        console.error("Vault init failed:", e);
        userStore.update(s => ({ ...s, authError: "Failed to open vault." }));
        return;
    }

    let idHash: string | null = null;
    try {
        // Init signal manager (identity generation/loading)
        idHash = await signalManager.init(password);
    } catch (e) {
        console.error("Signal init failed:", e);
    }

    if (idHash) {
        let chats: Record<string, Chat> = {};
        let myAlias: string | null = null;
        let myPfp: string | null = null;
        let sessionToken: string | null = null;

        const saved = await vaultLoad(`entropy_chats_${idHash}`);

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
            } catch (e) {
                userStore.update(s => ({ ...s, authError: "Corrupted vault data." }));
                return;
            }
        }

        userStore.update(s => ({ ...s, identityHash: idHash, chats, myAlias, myPfp, sessionToken, authError: null }));
        network.connect();
        startHeartbeat();

        const serverUrl = get(userStore).relayUrl;
        // Keys upload is no-op in manager but safe to call
        try { await signalManager.ensureKeysUploaded(serverUrl); } catch (e) { }
    } else {
        userStore.update(s => ({ ...s, authError: "Identity not found. please create one." }));
    }
};

export const createIdentity = async (password: string) => {
    try {
        console.debug("Starting identity creation...");
        await initCrypto(); // just loads wasm if needed
        await initVault(password);
        console.debug("Vault initialized.");
    } catch (e: any) {
        console.error("Vault initialization failed:", e);
        throw new Error(`Local vault setup failed: ${e.message || e}`);
    }

    let idHash;
    try {
        console.debug("Initializing Signal manager...");
        idHash = await signalManager.init(password);
        console.debug("Identity generated:", idHash);
    } catch (e: any) {
        console.error("Identity generation failed:", e);
        throw new Error(`Identity generation failed: ${e.message || e}`);
    }

    if (idHash) {
        userStore.update(s => ({ ...s, identityHash: idHash }));

        console.debug("Connecting to network...");
        network.connect();
        startHeartbeat();
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

            // Mining PoW for anti-spam/auth
            const pow = await minePoW(seed, difficulty, identityHash);

            network.sendJSON({
                type: 'auth',
                payload: { identity_hash: identityHash, seed: pow.seed, nonce: pow.nonce }
            });
        }

        // Post-auth catchup (online status, etc.) should be triggered 
        // by the auth_success message in NetworkLayer, not here by timeout.
    } catch (e) {
        console.error("Authentication failed:", e);
    } finally {
        isAuthInProgress = false;
    }
};

export const refreshDecoys = async (serverUrl: string) => {
    // No-op
};

export const burnAccount = async (serverUrl: string) => {
    if (confirm("DANGER: This will permanently purge your local data. Are you sure?")) {
        // Only local wipe
        localStorage.clear();
        await invoke('nuclear_reset');
        window.location.reload();
    }
};


export const exportVault = async () => {
    try {
        if (typeof window !== 'undefined' && (window as any).__TAURI_INTERNALS__) {
            const { save } = await import('@tauri-apps/plugin-dialog');
            const path = await save({
                defaultPath: `entropy_backup_${Date.now()}.db`,
                filters: [{
                    name: 'Entropy Database',
                    extensions: ['db']
                }]
            });

            if (path) {
                await invoke('export_database', { targetPath: path });
                alert("Backup exported successfully!");
            }
        } else {
            alert("Export not supported in web mode.");
        }
    } catch (e) {
        console.error("Export failed:", e);
        alert("Export failed: " + e);
    }
};

export const importVault = async () => {
    if (!confirm("WARNING: Importing a backup will OVERWRITE all current data. This cannot be undone. Continue?")) return;

    try {
        if (typeof window !== 'undefined' && (window as any).__TAURI_INTERNALS__) {
            const { open } = await import('@tauri-apps/plugin-dialog');
            const path = await open({
                multiple: false,
                filters: [{
                    name: 'Entropy Database',
                    extensions: ['db']
                }]
            });

            if (path) {
                await invoke('import_database', { srcPath: path });
                alert("Backup restored! The app will now restart.");
                window.location.reload();
            }
        } else {
            alert("Import not supported in web mode.");
        }
    } catch (e) {
        console.error("Import failed:", e);
        alert("Import failed: " + e);
    }
};
