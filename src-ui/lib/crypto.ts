import { invoke } from '@tauri-apps/api/core';

// Removed sodium dependency as we are no longer doing complex crypto in frontend

export const initCrypto = async () => {
    // No-op now
};

// Removed encryption/decryption keys

const HEX_TABLE = Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, '0'));

export const toHex = (bytes: Uint8Array): string => {
    let res = '';
    for (let i = 0; i < bytes.length; i++) {
        res += HEX_TABLE[bytes[i]];
    }
    return res;
};

export const fromHex = (hex: string): Uint8Array => {
    const cleanHex = hex.trim();
    const bytes = new Uint8Array(cleanHex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(cleanHex.substring(i * 2, i * 2 + 2), 16);
    }
    return bytes;
};

export const toBase64 = (bytes: Uint8Array): string => {
    let binary = '';
    const len = bytes.byteLength;
    const CHUNK_SIZE = 0x4000;
    for (let i = 0; i < len; i += CHUNK_SIZE) {
        const chunk = bytes.subarray(i, i + CHUNK_SIZE);
        binary += String.fromCharCode(...chunk);
    }
    return btoa(binary);
};

export const fromBase64 = (base64: string): Uint8Array => {
    try {
        const binString = atob(base64);
        const len = binString.length;
        const bytes = new Uint8Array(len);
        for (let i = 0; i < len; i++) {
            bytes[i] = binString.charCodeAt(i);
        }
        return bytes;
    } catch (e) {
        // Fallback for potentially unpadded or messy base64 from server
        try {
            const cleaned = base64.replace(/[\s\n\r]/g, '');
            const binString = atob(cleaned);
            const bytes = new Uint8Array(binString.length);
            for (let i = 0; i < binString.length; i++) {
                bytes[i] = binString.charCodeAt(i);
            }
            return bytes;
        } catch (e2) {
            console.error("Base64 decode failed", e2);
            return new Uint8Array(0);
        }
    }
};

export const sha256 = async (input: Uint8Array | string): Promise<string> => {
    const data = typeof input === 'string' ? new TextEncoder().encode(input) : input;
    return await invoke('crypto_sha256', { data: Array.from(data) });
};

export const minePoW = async (seed: string, difficulty: number = 3, context: string = ""): Promise<{ nonce: number, seed: string }> => {
    const result: any = await invoke('crypto_mine_pow', { seed, difficulty, context });
    return { nonce: result.nonce, seed: seed };
};
