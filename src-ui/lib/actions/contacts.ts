
import { get } from 'svelte/store';
import { userStore } from '../stores/user';
import { signalManager } from '../signal_manager';
import { network } from '../network';
import { minePoW } from '../crypto';
import { bulkDelete, sendReceipt } from './message_utils';
import type { PrivacySettings } from '../types';

export const statusTimeouts: Record<string, any> = {};
let heartbeatInterval: any = null;

export const markOnline = (peerHash: string) => {
    if (statusTimeouts[peerHash]) clearTimeout(statusTimeouts[peerHash]);

    userStore.update(s => {
        if (s.chats[peerHash]) {
            const updated = { ...s.chats[peerHash] };
            updated.isOnline = true;
            updated.lastSeen = undefined;
            s.chats[peerHash] = updated;
        }
        return { ...s, chats: { ...s.chats } };
    });

    statusTimeouts[peerHash] = setTimeout(() => {
        userStore.update(s => {
            if (s.chats[peerHash]) {
                const updated = { ...s.chats[peerHash] };
                updated.isOnline = false;
                updated.lastSeen = Date.now();
                s.chats[peerHash] = updated;
            }
            return { ...s, chats: { ...s.chats } };
        });
        delete statusTimeouts[peerHash];
    }, 25000);
};

export const startHeartbeat = () => {
    if (heartbeatInterval) clearInterval(heartbeatInterval);
    // 30s heartbeat
    heartbeatInterval = setInterval(() => {
        const state = get(userStore);
        if (state.identityHash && state.isConnected) {
            Object.keys(state.chats).forEach(peerHash => {
                if (!state.chats[peerHash].isGroup && state.privacySettings.lastSeen === 'everyone') {
                    setOnlineStatus(peerHash, true);
                }
            });
        } else if (!state.isConnected) {
            userStore.update(s => {
                Object.keys(s.chats).forEach(h => s.chats[h].isOnline = false);
                return s;
            });
        }
    }, 12000);

    // Disappearing messages cleanup (every 3s)
    setInterval(() => {
        const state = get(userStore);
        const now = Date.now();

        Object.keys(state.chats).forEach(h => {
            const chat = state.chats[h];
            if (chat.disappearingTimer && chat.disappearingTimer > 0) {
                const expiryTime = chat.disappearingTimer * 1000;
                const expiredIds = chat.messages
                    .filter(m => !m.isStarred && (now - m.timestamp) >= expiryTime)
                    .map(m => m.id);

                if (expiredIds.length > 0) {
                    bulkDelete(h, expiredIds);
                }
            }
        });
    }, 3000);
};

export const updateMyProfile = (alias: string, pfp: string | null) => {
    userStore.update(s => ({ ...s, myAlias: alias, myPfp: pfp }));
    const state = get(userStore);
    Object.keys(state.chats).forEach(peerHash => {
        if (!state.chats[peerHash].isGroup) broadcastProfile(peerHash);
    });
};

export const broadcastProfile = async (peerHash: string) => {
    const state = get(userStore);
    if (!state.myAlias && !state.myPfp) return;
    if (state.blockedHashes.includes(peerHash)) return;

    const profile = {
        type: 'profile_update',
        alias: state.myAlias,
        pfp: state.myPfp
    };

    try {
        const ciphertext = await signalManager.encrypt(peerHash, JSON.stringify(profile), get(userStore).relayUrl, true);
        network.sendVolatile(peerHash, new TextEncoder().encode(JSON.stringify(ciphertext)));
    } catch (e) { }
};

export const sendTypingStatus = async (peerIdentityHash: string, isTyping: boolean) => {
    const state = get(userStore);
    if (state.chats[peerIdentityHash]?.isGroup || state.blockedHashes.includes(peerIdentityHash)) return;

    const contentObj = { type: 'typing', isTyping };
    const ciphertextObj = await signalManager.encrypt(peerIdentityHash, JSON.stringify(contentObj), get(userStore).relayUrl, true);
    network.sendVolatile(peerIdentityHash, new TextEncoder().encode(JSON.stringify(ciphertextObj)));
};

export const setOnlineStatus = async (peerIdentityHash: string, isOnline: boolean) => {
    const state = get(userStore);
    if (state.blockedHashes.includes(peerIdentityHash)) return;
    const contentObj = { type: 'presence', isOnline };
    const ciphertextObj = await signalManager.encrypt(peerIdentityHash, JSON.stringify(contentObj), get(userStore).relayUrl, true);
    network.sendVolatile(peerIdentityHash, new TextEncoder().encode(JSON.stringify(ciphertextObj)));
};

export const togglePin = (peerHash: string) => userStore.update(s => { if (s.chats[peerHash]) s.chats[peerHash].isPinned = !s.chats[peerHash].isPinned; return { ...s, chats: { ...s.chats } }; });
export const toggleArchive = (peerHash: string) => userStore.update(s => { if (s.chats[peerHash]) s.chats[peerHash].isArchived = !s.chats[peerHash].isArchived; return { ...s, chats: { ...s.chats } }; });
export const toggleMute = (peerHash: string) => userStore.update(s => { if (s.chats[peerHash]) s.chats[peerHash].isMuted = !s.chats[peerHash].isMuted; return { ...s, chats: { ...s.chats } }; });
export const toggleVerification = (peerHash: string) => userStore.update(s => { if (s.chats[peerHash]) s.chats[peerHash].isVerified = !s.chats[peerHash].isVerified; return { ...s, chats: { ...s.chats } }; });
export const toggleStar = (peerHash: string, msgId: string) => userStore.update(s => {
    if (s.chats[peerHash]) {
        const msg = s.chats[peerHash].messages.find(m => m.id === msgId);
        if (msg) msg.isStarred = !msg.isStarred;
    }
    return { ...s, chats: { ...s.chats } };
});
export const setDisappearingTimer = async (peerHash: string, seconds: number | null) => {
    userStore.update(s => {
        if (s.chats[peerHash]) s.chats[peerHash].disappearingTimer = seconds || undefined;
        return { ...s, chats: { ...s.chats } };
    });

    const syncMsg = { type: 'disappearing_sync', seconds };
    try {
        const ciphertext = await signalManager.encrypt(peerHash, JSON.stringify(syncMsg), get(userStore).relayUrl, true);
        network.sendBinary(peerHash, new TextEncoder().encode(JSON.stringify(ciphertext)));
    } catch (e) { }
};

export const setLocalNickname = (peerHash: string, nickname: string | null) => {
    userStore.update(s => {
        if (s.chats[peerHash]) s.chats[peerHash].localNickname = nickname || undefined;
        return { ...s, chats: { ...s.chats } };
    });
};

export const bulkStar = (peerHash: string, msgIds: string[]) => userStore.update(s => {
    if (s.chats[peerHash]) {
        s.chats[peerHash].messages.forEach(m => { if (msgIds.includes(m.id)) m.isStarred = true; });
    }
    return { ...s, chats: { ...s.chats } };
});

export const toggleBlock = (peerHash: string) => userStore.update(s => {
    const isBlocked = s.blockedHashes.includes(peerHash);
    if (isBlocked) s.blockedHashes = s.blockedHashes.filter(h => h !== peerHash);
    else s.blockedHashes = [...s.blockedHashes, peerHash];
    return { ...s };
});

export const updatePrivacy = (settings: Partial<PrivacySettings>) => userStore.update(s => ({ ...s, privacySettings: { ...s.privacySettings, ...settings } }));

export const registerGlobalNickname = async (nickname: string) => {
    const state = get(userStore);
    if (!state.identityHash) return;

    try {
        const serverUrl = get(userStore).relayUrl;
        const challengeRes = await fetch(`${serverUrl}/pow/challenge?nickname=${encodeURIComponent(nickname)}&identity_hash=${state.identityHash}`);
        const { seed, difficulty } = await challengeRes.json();
        const { nonce } = await minePoW(seed, difficulty, nickname);
        // Signature might be expected by backend, but we send stub
        const signature = await signalManager.signMessage(nickname);

        const response = await fetch(`${serverUrl}/nickname/register`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-PoW-Seed': seed,
                'X-PoW-Nonce': nonce.toString()
            },
            body: JSON.stringify({
                nickname,
                identity_hash: state.identityHash,
                identityKey: "plaintext_no_key", // Placeholder
                signature
            })
        });

        const result = await response.json();
        if (result.status === 'success') {
            console.log("Global nickname registered:", nickname);
            userStore.update(s => ({ ...s, myAlias: nickname }));
            return { success: true };
        } else {
            console.error("Nickname registration failed:", result.error);
            return { success: false, error: result.error };
        }
    } catch (e) {
        console.error("Nickname registration error:", e);
        return { success: false, error: "Network error" };
    }
};

export const lookupNickname = async (nickname: string): Promise<string | null> => {
    const input = nickname.trim();
    if (!input) return null;

    // Fast-path: if it's already a hash, just return it
    if (input.length === 64 && /^[0-9a-fA-F]+$/.test(input)) {
        return input;
    }

    try {
        const serverUrl = get(userStore).relayUrl;
        const response = await fetch(`${serverUrl}/nickname/lookup?name=${encodeURIComponent(input)}`);
        if (response.status === 200) {
            const data = await response.json();
            return data[nickname] || data.identity_hash || null;
        }
        return null;
    } catch (e) {
        return null;
    }
};

export const verifyContact = async (peerHash: string, isVerified: boolean) => {
    // Disabled in plaintext
};

export const startChat = (peerHash: string, alias?: string) => {
    userStore.update(s => {
        if (!s.chats[peerHash]) {
            s.chats[peerHash] = {
                peerHash,
                peerAlias: alias || peerHash.slice(0, 8),
                messages: [],
                unreadCount: 0
            };
        } else if (alias && s.chats[peerHash].peerAlias === s.chats[peerHash].peerHash.slice(0, 8)) {
            s.chats[peerHash].peerAlias = alias;
        }

        const unreadIds: string[] = [];
        s.chats[peerHash].messages.forEach(m => {
            if (!m.isMine && m.status !== 'read') {
                m.status = 'read';
                unreadIds.push(m.id);
            }
        });

        s.chats[peerHash].unreadCount = 0;
        if (unreadIds.length > 0) {
            sendReceipt(peerHash, unreadIds, 'read');
        }

        return { ...s, activeChatHash: peerHash, chats: { ...s.chats } };
    });
};

export const updateAlias = (peerHash: string, newAlias: string) => {
    userStore.update(s => { if (s.chats[peerHash]) s.chats[peerHash].peerAlias = newAlias; return s; });
};
