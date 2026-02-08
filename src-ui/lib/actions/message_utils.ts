import { get } from 'svelte/store';
import { userStore } from '../stores/user';
import { attachmentStore } from '../attachment_store';
import { signalManager } from '../signal_manager';
import { network } from '../network';
import { toHex } from '../utils';
import type { Message } from '../types';

export const addMessage = (peerHash: string, msg: Message) => {
    if (msg.attachment?.data) attachmentStore.put(msg.id, msg.attachment.data).catch(e => { });

    userStore.update(s => {
        const chat = s.chats[peerHash];
        if (!chat) {
            s.chats[peerHash] = { peerHash, peerAlias: peerHash.slice(0, 8), messages: [], unreadCount: 0 };
        } else if (chat.messages.some(m => m.id === msg.id)) {
            return s;
        }

        const updatedChat = { ...s.chats[peerHash] };
        updatedChat.messages = [...updatedChat.messages, msg];

        if (!msg.isMine) {
            if (s.activeChatHash === peerHash) {
                // If viewing, mark as read and send receipt
                msg.status = 'read';
                sendReceipt(peerHash, [msg.id], 'read');
            } else {
                updatedChat.unreadCount = (updatedChat.unreadCount || 0) + 1;

                if (typeof window !== 'undefined' && (window as any).__TAURI_INTERNALS__) {
                    import('@tauri-apps/plugin-notification').then(({ sendNotification, isPermissionGranted }) => {
                        isPermissionGranted().then((granted: boolean) => {
                            if (granted) {
                                sendNotification({
                                    title: `Message from ${updatedChat.peerAlias}`,
                                    body: msg.content.length > 50 ? msg.content.substring(0, 47) + '...' : msg.content
                                });
                            }
                        });
                    });
                }
            }
        }

        s.chats[peerHash] = updatedChat;
        return { ...s, chats: { ...s.chats } };
    });
};

export const bulkDelete = (peerHash: string, msgIds: string[]) => {
    msgIds.forEach(id => attachmentStore.delete(id).catch(() => { }));
    userStore.update(s => {
        if (s.chats[peerHash]) {
            s.chats[peerHash].messages = s.chats[peerHash].messages.filter(m => !msgIds.includes(m.id));
        }
        return { ...s, chats: { ...s.chats } };
    });
};

export const deleteMessage = (peerHash: string, msgId: string) => bulkDelete(peerHash, [msgId]);

export const sendReceipt = async (peerHash: string, msgIds: string[], status: 'delivered' | 'read') => {
    const state = get(userStore);
    if (state.blockedHashes.includes(peerHash)) return;
    if (status === 'read' && !state.privacySettings.readReceipts) return;
    if (msgIds.length === 0) return;
    const receipt = { type: 'receipt', msgIds, status };
    try {
        const ciphertext = await signalManager.encrypt(peerHash, JSON.stringify(receipt), get(userStore).relayUrl, true);
        network.sendVolatile(peerHash, new TextEncoder().encode(JSON.stringify(ciphertext)));
    } catch (e) { }
};

export const downloadAttachment = async (msgId: string, bundle: any) => {
    try {
        console.debug("[Download] Starting for msgId:", msgId);
        const encrypted = await attachmentStore.get(msgId);
        if (!encrypted) {
            console.error("[Download] Attachment not found in store for msgId:", msgId);
            throw new Error("Attachment not found locally");
        }

        console.debug("[Download] Data retrieved, decrypting...");
        const decrypted = await signalManager.decryptMedia(encrypted, bundle);

        console.debug("[Download] Creating blob and triggering click...");
        const blob = new Blob([decrypted as any], { type: bundle.file_type || 'application/octet-stream' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = bundle.file_name || 'download';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        console.debug("[Download] Successfully triggered.");
    } catch (e) {
        console.error("[Download] Failed:", e);
    }
};

export const markAsDownloaded = (chatId: string, msgId: string) => {
    userStore.update(s => {
        const chat = s.chats[chatId];
        if (chat) {
            const m = chat.messages.find(x => x.id === msgId);
            if (m && m.attachment) {
                m.attachment.isDownloaded = true;
            }
        }
        return { ...s, chats: { ...s.chats } };
    });
};
