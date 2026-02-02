import { describe, it, expect, vi, beforeEach } from 'vitest';
import { SignalManager } from '../lib/signal_manager';
import { invoke } from '@tauri-apps/api/core';

vi.mock('@tauri-apps/api/core', () => ({
    invoke: vi.fn(),
}));

vi.mock('../lib/crypto', () => ({
    minePoW: vi.fn().mockResolvedValue({ nonce: 123, seed: 'test' }),
    sha256: vi.fn().mockResolvedValue('hash'),
    fromBase64: vi.fn().mockReturnValue(new Uint8Array(32)),
    deriveVaultKey: vi.fn(),
}));

vi.mock('../lib/secure_storage', () => ({
    secureLoad: vi.fn(),
    secureStore: vi.fn(),
}));

describe('SignalManager', () => {
    let sm: SignalManager;

    beforeEach(() => {
        vi.clearAllMocks();
        sm = new SignalManager();
        // @ts-ignore
        global.fetch = vi.fn().mockResolvedValue({
            ok: true,
            json: async () => ({ seed: 's', difficulty: 1 })
        });
        localStorage.clear();
    });

    it('should cap pre-keys at 100 for upload', async () => {
        const manyPreKeys = Array.from({ length: 150 }, (_, i) => ({
            key_id: i,
            public_key: `pub${i}`
        }));

        const mockBundle = {
            registration_id: 1,
            identity_key: 'ik',
            pq_identity_key: 'pqik',
            signed_pre_key: {
                key_id: 1,
                public_key: 'spk',
                pq_public_key: 'pqspk',
                signature: 'sig'
            },
            pre_keys: manyPreKeys
        };

        (sm as any)._cachedBundle = mockBundle;
        (sm as any).userIdentity = 'me';

        vi.mocked(invoke).mockResolvedValue('signature' as any);

        await sm.ensureKeysUploaded('http://server');

        const lastCall = vi.mocked(fetch).mock.calls.find(call => call[0].toString().endsWith('/keys/upload'));
        const body = JSON.parse(lastCall![1]!.body as string);

        expect(body.preKeys.length).toBe(100);
        expect(body.preKeys[0].keyId).toBe(50); // Should be the last 100
        expect(body.preKeys[99].keyId).toBe(149);
    });
});
