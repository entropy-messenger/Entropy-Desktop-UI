
import { writable } from 'svelte/store';
import type { Chat, Message, PrivacySettings } from '../types';

export interface AppState {
    identityHash: string | null;
    myAlias: string | null;
    myPfp: string | null;
    chats: Record<string, Chat>;
    isConnected: boolean;
    activeChatHash: string | null;
    searchQuery: string;
    replyingTo: Message | null;
    blockedHashes: string[];
    privacySettings: PrivacySettings;
    sessionToken: string | null;
    connectionStatus: 'disconnected' | 'connecting' | 'mining' | 'connected';
    authError: string | null;
    relayUrl: string;
}

const initialState: AppState = {
    identityHash: null,
    myAlias: null,
    myPfp: null,
    chats: {},
    isConnected: false,
    activeChatHash: null,
    searchQuery: "",
    replyingTo: null,
    blockedHashes: [],
    privacySettings: {
        readReceipts: true,
        lastSeen: 'everyone',
        profilePhoto: 'everyone',
        routingMode: 'direct',
        proxyUrl: 'socks5://127.0.0.1:9050'
    },
    sessionToken: null,
    connectionStatus: 'disconnected',
    authError: null,
    relayUrl: import.meta.env.VITE_RELAY_URL || 'http://localhost:8080'
};

export const userStore = writable<AppState>(initialState);
