import { describe, it, expect, beforeEach } from 'vitest';
import { userStore } from '../lib/stores/user';
import { get } from 'svelte/store';

describe('userStore', () => {
    beforeEach(() => {
        userStore.set({
            identityHash: null,
            myAlias: null,
            myPfp: null,
            chats: {},
            isConnected: false,
            activeChatHash: null,
            searchQuery: "",
            replyingTo: null,
            blockedHashes: [],
            myGlobalNickname: null,
            nicknameExpiry: null,
            privacySettings: {
                readReceipts: true,
                lastSeen: 'everyone',
                profilePhoto: 'everyone',
                routingMode: 'direct',
                proxyUrl: 'socks5://127.0.0.1:9050',
                decoyMode: true,
                forceTurn: false,
                iceServers: ['stun:stun.l.google.com:19302']
            },
            sessionToken: null,
            connectionStatus: 'disconnected',
            authError: null,
            keysMissing: false,
            relayUrl: 'http://localhost:8080'
        });
    });

    it('should have correct initial state', () => {
        const state = get(userStore);
        expect(state.identityHash).toBeNull();
        expect(state.isConnected).toBe(false);
    });

    it('should update state correctly', () => {
        userStore.update(s => ({ ...s, identityHash: 'test-hash', isConnected: true }));
        const state = get(userStore);
        expect(state.identityHash).toBe('test-hash');
        expect(state.isConnected).toBe(true);
    });

    it('should handle privacy settings updates', () => {
        userStore.update(s => ({
            ...s,
            privacySettings: { ...s.privacySettings, readReceipts: false }
        }));
        const state = get(userStore);
        expect(state.privacySettings.readReceipts).toBe(false);
        expect(state.privacySettings.decoyMode).toBe(true);
    });
});
