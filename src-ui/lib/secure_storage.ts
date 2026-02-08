
import { invoke } from '@tauri-apps/api/core';

declare global {
    interface Window {
        __TAURI_INTERNALS__?: unknown;
    }
}

const isTauri = () => typeof window !== 'undefined' && !!window.__TAURI_INTERNALS__;

// Stubbed secure storage interface - no keyring used
export const secureStore = async (key: string, value: string): Promise<void> => {
    // No-op or log warning
    console.warn("Secure store called in plaintext mode. Ignoring.");
};

export const secureLoad = async (key: string): Promise<string | null> => {
    // Return null
    return null;
};

export const initVault = async (passphrase: string): Promise<void> => {
    if (isTauri()) {
        await invoke('init_vault', { passphrase });
    }
};

export const vaultSave = async (key: string, value: string): Promise<void> => {
    if (isTauri()) {
        try {
            await invoke('vault_save', { key, value });
        } catch (e) {
            console.error("[Vault] Save failed:", e);
            throw e;
        }
    } else {
        if (import.meta.env.DEV) {
            localStorage.setItem(`vlt:${key}`, value);
        }
    }
};

export const vaultLoad = async (key: string): Promise<string | null> => {
    if (isTauri()) {
        try {
            const val = await invoke('vault_load', { key });
            return val as string | null;
        } catch (e) {
            console.warn("[Vault] Load failed (or empty):", e);
            return null;
        }
    } else {
        if (import.meta.env.DEV) {
            return localStorage.getItem(`vlt:${key}`);
        }
        return null;
    }
};

export const vaultDelete = async (key: string): Promise<void> => {
    if (isTauri()) {
        try {
            await invoke('vault_delete', { key });
        } catch (e) {
            console.error("[Vault] Delete failed:", e);
        }
    } else {
        if (import.meta.env.DEV) {
            localStorage.removeItem(`vlt:${key}`);
        }
    }
};

export const hasVault = async (): Promise<boolean> => {
    if (isTauri()) {
        try {
            return await invoke('vault_exists');
        } catch (e) {
            console.error("[hasVault] Check failed:", e);
            return false;
        }
    }
    // Fallback for dev mode without backend
    return !!localStorage.getItem('plaintext_identity');
};
