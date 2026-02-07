
import { toBase64, fromBase64 } from './crypto';
import { vaultSave, vaultLoad, vaultDelete } from './secure_storage';

export class AttachmentStore {
    // No encryption key needed for plaintext storage
    setEncryptionKey(key: Uint8Array | null) {
        // No-op
    }

    async init(): Promise<void> {
        // No-op, vault is initialized at app start
    }

    async put(id: string, data: Uint8Array): Promise<void> {
        // Store as base64 string in the main DB
        const b64 = toBase64(data);
        await vaultSave(`att_${id}`, b64);
    }

    async get(id: string): Promise<Uint8Array | null> {
        const b64 = await vaultLoad(`att_${id}`);
        if (!b64) return null;
        return fromBase64(b64);
    }

    async delete(id: string): Promise<void> {
        await vaultDelete(`att_${id}`);
    }
}

export const attachmentStore = new AttachmentStore();
