
import { get } from 'svelte/store';
import { userStore } from '../stores/user';
import { signalManager } from '../signal_manager';
import { network } from '../network';
import { attachmentStore } from '../attachment_store';
import { invoke } from '@tauri-apps/api/core';
import type { Message, ServerMessage } from '../types';
import { parseLinkPreview, fromHex } from '../utils';
import { fromBase64, toBase64 } from '../crypto';
import { markOnline, setOnlineStatus, broadcastProfile, statusTimeouts } from './contacts';
import { addMessage, sendReceipt } from './message_utils';

export { addMessage, bulkDelete, deleteMessage, downloadAttachment, sendReceipt } from './message_utils';

export const setReplyingTo = (msg: Message | null) => userStore.update(s => ({ ...s, replyingTo: msg }));
export const typingTimeouts: Record<string, any> = {};

const CHUNK_SIZE = 32 * 1024; // 32KB chunks
const fragmentReassembly: Record<string, {
    total: number,
    chunks: Record<number, Uint8Array>,
    timestamp: number
}> = {};

// Helper to wrap plaintext content
const createPayload = (type: string, content: any, id: string, replyTo?: any) => {
    return { type, content, id, replyTo, timestamp: Date.now() };
};

export const sendMessage = async (destId: string, content: string) => {
    const state = get(userStore);
    if (!state.identityHash) return;
    const chat = state.chats[destId];
    if (state.blockedHashes.includes(destId)) return;
    if (chat?.isGroup) return sendGroupMessage(destId, content);

    try {
        const msgId = crypto.randomUUID();
        const linkPreview = await parseLinkPreview(content);
        let replyToData = undefined;
        if (state.replyingTo) {
            replyToData = {
                id: state.replyingTo.id,
                content: state.replyingTo.content,
                senderAlias: state.replyingTo.senderAlias,
                type: state.replyingTo.type
            };
        }

        const payload = { type: 'text_msg', content, id: msgId, replyTo: replyToData, linkPreview };
        // "Encrypt" (wrap in plaintext container)
        const ciphertextObj = await signalManager.encrypt(destId, JSON.stringify(payload), state.relayUrl);

        // Send binary (legacy path used by network layer for direct messages)
        network.sendBinary(destId, new TextEncoder().encode(JSON.stringify(ciphertextObj)));

        const msg: Message = {
            id: msgId,
            timestamp: Date.now(),
            senderHash: state.identityHash,
            content,
            type: 'text',
            isMine: true,
            status: 'sent',
            replyTo: replyToData,
            linkPreview
        };
        addMessage(destId, msg);
        setReplyingTo(null);
    } catch (e) {
        console.error("Send failed", e);
    }
};

export const sendGroupMessage = async (groupId: string, content: string) => {
    const state = get(userStore);
    const group = state.chats[groupId];
    if (!group?.isGroup || !group.members) return;

    const msgId = crypto.randomUUID();
    let replyToData = undefined;
    if (state.replyingTo) {
        replyToData = {
            id: state.replyingTo.id,
            content: state.replyingTo.content,
            senderAlias: state.replyingTo.senderAlias,
            type: state.replyingTo.type
        };
    }

    try {
        const targets = [];
        for (const member of group.members!) {
            if (member === state.identityHash) continue;
            const payload = {
                type: 'group_message_v2',
                groupId,
                sender: state.identityHash,
                content: content,
                id: msgId,
                replyTo: replyToData
            };
            // Encrypt per member (Sealed Sender style)
            const wrapped = await signalManager.encrypt(member, JSON.stringify(payload), state.relayUrl);
            targets.push({ to: member, body: wrapped.body, msg_type: wrapped.type });
        }

        if (targets.length > 0) {
            network.sendJSON({ type: 'group_multicast', targets });
        }
    } catch (e) {
        console.error("Group Send Failed:", e);
    }

    const msg: Message = {
        id: msgId,
        timestamp: Date.now(),
        senderHash: state.identityHash!,
        content,
        type: 'text', // Changed from default to text
        groupId,
        isMine: true,
        status: 'sent',
        replyTo: replyToData
    };
    addMessage(groupId, msg);
    setReplyingTo(null);
};

export const sendFile = async (destId: string, file: File) => {
    const state = get(userStore);
    if (!state.identityHash) return;
    const chat = state.chats[destId];

    const reader = new FileReader();
    reader.onload = async () => {
        const buffer = reader.result as ArrayBuffer;
        const uint8 = new Uint8Array(buffer);

        // Uses simplified encryptMedia (returns hex of data)
        const { ciphertext, bundle } = await signalManager.encryptMedia(uint8, file.name, file.type);
        const msgId = crypto.randomUUID();

        const contentObj = {
            type: 'file_v2',
            id: msgId,
            bundle,
            data: ciphertext,
            size: uint8.length
        };

        if (chat?.isGroup) {
            const targets = [];
            for (const member of chat.members!) {
                if (member === state.identityHash) continue;
                const payload = { ...contentObj, groupId: destId };
                const wrapped = await signalManager.encrypt(member, JSON.stringify(payload), state.relayUrl);
                targets.push({ to: member, body: wrapped.body, msg_type: wrapped.type });
            }
            network.sendJSON({ type: 'group_multicast', targets });
        } else {
            const wrapped = await signalManager.encrypt(destId, JSON.stringify(contentObj), state.relayUrl);
            network.sendBinary(destId, new TextEncoder().encode(JSON.stringify(wrapped)));
        }

        const msg: Message = {
            id: msgId,
            timestamp: Date.now(),
            senderHash: state.identityHash!,
            content: `File: ${file.name}`,
            type: 'file',
            groupId: chat?.isGroup ? destId : undefined,
            attachment: { fileName: file.name, fileType: file.type, size: file.size, data: uint8 },
            isMine: true, status: 'sent'
        };
        addMessage(destId, msg);
    };
    reader.readAsArrayBuffer(file);
};

export const sendVoiceNote = async (destId: string, audioBlob: Blob) => {
    const state = get(userStore);
    if (!state.identityHash) return;
    const chat = state.chats[destId];

    const buffer = await audioBlob.arrayBuffer();
    const uint8 = new Uint8Array(buffer);
    const msgId = crypto.randomUUID();

    const contentObj = {
        type: 'voice_note',
        data: toBase64(uint8),
        id: msgId,
        fileName: 'voice_note.wav',
        fileType: 'audio/wav',
        size: uint8.length
    };

    if (chat?.isGroup) {
        const targets = [];
        for (const member of chat.members!) {
            if (member === state.identityHash) continue;
            const payload = { ...contentObj, groupId: destId };
            const wrapped = await signalManager.encrypt(member, JSON.stringify(payload), state.relayUrl);
            targets.push({ to: member, body: wrapped.body, msg_type: wrapped.type });
        }
        network.sendJSON({ type: 'group_multicast', targets });
    } else {
        const wrapped = await signalManager.encrypt(destId, JSON.stringify(contentObj), state.relayUrl);
        network.sendBinary(destId, new TextEncoder().encode(JSON.stringify(wrapped)), { id: msgId });
    }

    const msg: Message = {
        id: msgId,
        timestamp: Date.now(),
        senderHash: state.identityHash,
        content: "[Voice Note]",
        type: 'voice_note',
        groupId: chat?.isGroup ? destId : undefined,
        attachment: { fileName: 'voice_note.wav', fileType: 'audio/wav', size: uint8.length, data: uint8 },
        isMine: true,
        status: 'sent'
    };
    await attachmentStore.put(msgId, uint8);
    addMessage(destId, msg);
};

// Process decrypted/plaintext payload
const processPayload = async (senderHash: string, payloadStr: string, groupId?: string, msgId?: string, replyToIn?: any) => {
    const state = get(userStore);
    if (state.blockedHashes.includes(senderHash)) return;

    let content = payloadStr;
    let type: Message['type'] = 'text';
    let attachment: any = undefined;
    let actualGroupId: string | undefined = groupId;
    let incomingMsgId = msgId || crypto.randomUUID();
    let replyTo = replyToIn;
    let linkPreview = undefined;

    try {
        const parsed = JSON.parse(payloadStr);
        if (parsed.id) incomingMsgId = parsed.id;
        if (parsed.replyTo) replyTo = parsed.replyTo;
        if (parsed.linkPreview) linkPreview = parsed.linkPreview;
        if (parsed.sender) senderHash = parsed.sender;

        if (parsed.type === 'group_invite' || parsed.type === 'group_invite_v2') {
            userStore.update(s => {
                if (!s.chats[parsed.groupId]) {
                    s.chats[parsed.groupId] = { peerHash: parsed.groupId, peerAlias: parsed.name, messages: [], unreadCount: 1, isGroup: true, members: parsed.members };
                }
                return s;
            });
            return;
        }

        actualGroupId = parsed.groupId || groupId;
        if (parsed.type === 'group_message' || parsed.type === 'group_message_v2' || parsed.type === 'text_msg') {
            content = parsed.content || parsed.body || parsed.m || content;
        } else if (parsed.type === 'file' || parsed.type === 'voice_note') {
            type = parsed.type;
            content = parsed.type === 'file' ? `File: ${parsed.fileName}` : "Voice Note";
            const attachmentData = fromBase64(parsed.data);
            attachment = {
                fileName: parsed.fileName || (parsed.type === 'voice_note' ? 'voice_note.wav' : 'file'),
                fileType: parsed.fileType || (parsed.type === 'voice_note' ? 'audio/wav' : 'application/octet-stream'),
                size: parsed.size || attachmentData.length,
                data: attachmentData
            };
            await attachmentStore.put(incomingMsgId, attachmentData);
        } else if (parsed.type === 'file_v2') {
            type = 'file';
            const size = parsed.size || (parsed.bundle && parsed.bundle.file_size) || 0;
            content = `File: ${parsed.bundle.file_name}`;
            attachment = {
                fileName: parsed.bundle.file_name,
                fileType: parsed.bundle.file_type,
                size: size,
                bundle: parsed.bundle,
                isV2: true
            };
            await attachmentStore.put(incomingMsgId, fromHex(parsed.data));
        } else if (parsed.type === 'typing') {
            if (typingTimeouts[senderHash]) clearTimeout(typingTimeouts[senderHash]);

            userStore.update(s => {
                if (s.chats[senderHash]) {
                    const updated = { ...s.chats[senderHash] };
                    updated.isTyping = parsed.isTyping;
                    s.chats[senderHash] = updated;
                }
                return { ...s, chats: { ...s.chats } };
            });

            if (parsed.isTyping) {
                typingTimeouts[senderHash] = setTimeout(() => {
                    userStore.update(s => {
                        if (s.chats[senderHash]) {
                            const updated = { ...s.chats[senderHash] };
                            updated.isTyping = false;
                            s.chats[senderHash] = updated;
                        }
                        return { ...s, chats: { ...s.chats } };
                    });
                    delete typingTimeouts[senderHash];
                }, 6000); // 6s safety timeout
            }
            return;
        } else if (parsed.type === 'presence') {
            if (parsed.isOnline) {
                markOnline(senderHash);
                if (!state.chats[senderHash]?.pfp) broadcastProfile(senderHash);
            } else {
                if (statusTimeouts[senderHash]) clearTimeout(statusTimeouts[senderHash]);
                userStore.update(s => {
                    if (s.chats[senderHash]) {
                        const updated = { ...s.chats[senderHash] };
                        updated.isOnline = false;
                        updated.lastSeen = Date.now();
                        s.chats[senderHash] = updated;
                    }
                    return { ...s, chats: { ...s.chats } };
                });
            }
            return;
        } else if (parsed.type === 'profile_update') {
            userStore.update(s => {
                if (s.chats[senderHash]) {
                    const updated = { ...s.chats[senderHash] };
                    if (parsed.alias) updated.peerAlias = parsed.alias;
                    if (parsed.pfp) updated.pfp = parsed.pfp;
                    s.chats[senderHash] = updated;
                }
                return { ...s, chats: { ...s.chats } };
            });
            return;
        } else if (parsed.type === 'receipt') {
            // Receipt handling
            userStore.update(s => {
                if (s.chats[senderHash]) {
                    const updatedChat = { ...s.chats[senderHash] };
                    updatedChat.messages = updatedChat.messages.map(m => {
                        const ids = Array.isArray(parsed.msgIds) ? parsed.msgIds : [parsed.msgId];
                        if (ids.includes(m.id) && (parsed.status === 'read' || m.status === 'sent')) {
                            return { ...m, status: parsed.status };
                        }
                        return m;
                    });
                    s.chats[senderHash] = updatedChat;
                }
                return { ...s, chats: { ...s.chats } };
            });
            return;
        }
        // Removed call_log handling
    } catch (e) {
        // Not JSON, assume plain text
    }

    const msg: Message = {
        id: incomingMsgId, timestamp: Date.now(), senderHash,
        senderAlias: state.chats[senderHash]?.peerAlias, content, type, attachment,
        groupId: actualGroupId, isMine: false, status: 'delivered', replyTo, linkPreview
    };
    addMessage(actualGroupId || senderHash, msg);

    if (!actualGroupId) {
        // Send delivered receipt
        sendReceipt(senderHash, [incomingMsgId], 'delivered');
    }
};

export const handleIncomingMessage = async (payload: Uint8Array | ServerMessage, overrideSender?: string): Promise<void> => {
    try {
        const state = get(userStore);
        if (!state.identityHash) return;

        let incomingObj: any;
        if (payload instanceof Uint8Array) {
            let lastIndex = payload.length;
            while (lastIndex > 0 && payload[lastIndex - 1] === 0) lastIndex--;
            const trimmedPayload = payload.slice(0, lastIndex);
            const payloadStr = new TextDecoder().decode(trimmedPayload);
            try { incomingObj = JSON.parse(payloadStr); } catch (e) { return; }
        } else {
            incomingObj = payload;
        }

        if (incomingObj.type === 'binary_payload' && incomingObj.data_hex) {
            console.debug("[Messaging] Unwrapping binary_payload...");
            const decoded = fromHex(incomingObj.data_hex);
            return handleIncomingMessage(decoded, incomingObj.sender);
        }

        let senderHash = overrideSender || incomingObj.sender || "unknown";

        // Handle generic fragments
        if (incomingObj.type === 'msg_fragment') {
            const fragId = incomingObj.fragmentId;
            if (!fragmentReassembly[fragId]) {
                fragmentReassembly[fragId] = {
                    total: incomingObj.total,
                    chunks: {},
                    timestamp: Date.now()
                };
            }
            const assembly = fragmentReassembly[fragId];
            assembly.chunks[incomingObj.index] = fromBase64(incomingObj.data);

            if (Object.keys(assembly.chunks).length === assembly.total) {
                let totalLen = 0;
                for (let i = 0; i < assembly.total; i++) totalLen += assembly.chunks[i].length;
                const fullData = new Uint8Array(totalLen);
                let offset = 0;
                for (let i = 0; i < assembly.total; i++) {
                    fullData.set(assembly.chunks[i], offset);
                    offset += assembly.chunks[i].length;
                }
                delete fragmentReassembly[fragId];
                // Process the reassembled message as if it came in one piece
                return handleIncomingMessage(fullData, senderHash);
            }
            return; // Wait for more fragments
        }

        // Handle group messages V2
        if (incomingObj.type === 'group_message_v2') {
            await processPayload(incomingObj.sender, incomingObj.body, incomingObj.groupId, incomingObj.id, incomingObj.replyTo);
            return;
        }

        // Handle direct messages
        // Try to "decrypt" (unwrap plaintext)
        const decrypted = await signalManager.decrypt(senderHash, incomingObj);

        if (decrypted) {
            // If we got a result, it means the structure matched our plaintext wrapper
            // The result from 'decrypt' is the INNER JSON object (or string)
            // We need to pass THAT to processPayload, but processPayload expects string.
            // signalManager.decrypt returns JSON.parse(body).
            // So we need to stringify it back or update processPayload to handle objects.
            // Actually processPayload mainly does JSON.parse. 
            // Let's create a helper or just pass JSON string.
            const bodyStr = typeof decrypted === 'string' ? decrypted : JSON.stringify(decrypted);
            await processPayload(senderHash, bodyStr);
        } else {
            // Fallback: treat raw as message?
        }

    } catch (e) { }
};
