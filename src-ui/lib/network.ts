
import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import { get } from 'svelte/store';
import { userStore } from './stores/user';
import * as logicStore from './store';
import type { ServerMessage } from './types';

export class NetworkLayer {
    private url: string = "";
    private retryCount = 0;
    private maxRetries = 5;
    private isAuthenticated = false;
    private isConnected = false;
    private lastActivity = Date.now();

    constructor() {
        listen('network-msg', (event) => {
            this.handleMessage(event.payload as string);
        });

        listen('network-bin', (event) => {
            this.handleBinaryMessage(new Uint8Array(event.payload as number[]));
        });

        listen('network-status', (event) => {
            if (event.payload === 'disconnected') {
                this.onDisconnect();
            }
        });
    }

    private connectingPromise: Promise<void> | null = null;

    async connect() {
        if (this.isConnected) return;
        if (this.connectingPromise) return this.connectingPromise;

        this.connectingPromise = (async () => {
            try {
                this.url = get(userStore).relayUrl.replace('http', 'ws') + '/ws';

                let proxyUrl = undefined;
                const state = get(userStore) as any;
                if (state.privacySettings.routingMode !== 'direct') {
                    proxyUrl = state.privacySettings.proxyUrl;
                    if (state.privacySettings.routingMode === 'tor') {
                        proxyUrl = 'socks5://127.0.0.1:9050';
                    }
                }

                console.log(`Commanding native connection to ${this.url} (Proxy: ${proxyUrl || 'none'})...`);
                await invoke('connect_network', { url: this.url, proxyUrl });
                this.isConnected = true;
                this.onConnect();
            } catch (e) {
                console.error("Native connection failed:", e);
                this.retry();
            } finally {
                this.connectingPromise = null;
            }
        })();

        return this.connectingPromise;
    }

    private stabilityTimer: any = null;

    private onConnect() {
        console.log('Native network layer connected');

        if (this.stabilityTimer) clearTimeout(this.stabilityTimer);
        this.stabilityTimer = setTimeout(() => {
            console.log("Connection stabilized. Resetting retry count.");
            this.retryCount = 0;
        }, 5000);

        userStore.update((s: any) => ({ ...s, isConnected: true }));

        const state = get(userStore) as any;
        if (state.identityHash) {
            logicStore.authenticate(state.identityHash);
        }
    }

    private onDisconnect() {
        console.log('Native network layer disconnected');

        if (this.stabilityTimer) {
            clearTimeout(this.stabilityTimer);
            this.stabilityTimer = null;
        }

        const wasAuthenticated = this.isAuthenticated;
        this.isConnected = false;
        this.isAuthenticated = false;

        userStore.update((s: any) => {
            const newState = {
                ...s,
                isConnected: false,
                connectionStatus: 'disconnected'
            };
            if (!wasAuthenticated && s.sessionToken) {
                console.warn("[Network] Disconnected while unauthenticated. Clearing session token for fallback.");
                newState.sessionToken = null;
            }
            return newState;
        });

        this.retry();
    }

    private retry() {
        if (this.retryCount < this.maxRetries) {
            this.retryCount++;
            setTimeout(() => this.connect(), 2000 * this.retryCount);
        }
    }

    private async handleMessage(text: string) {
        try {
            const msg: ServerMessage = JSON.parse(text);
            if (msg.type === 'dummy_ack' || (msg as any).type === 'dummy_pacing') return;
            await this.onJsonMessage(msg);
        } catch (e) {
            console.error("Failed to parse native JSON msg", e);
        }
    }

    private async handleBinaryMessage(payload: Uint8Array) {
        await logicStore.handleIncomingMessage(payload);
    }

    private async onJsonMessage(msg: any) {
        this.lastActivity = Date.now();
        console.debug("[Network] Received JSON:", msg.type, msg);
        if (msg.type === 'auth_success') {
            const token = msg.session_token;
            const id = msg.identity_hash;
            console.log("Authenticated as:", id);
            this.isAuthenticated = true;

            userStore.update((s: any) => ({
                ...s,
                sessionToken: token || s.sessionToken,
                connectionStatus: 'connected'
            }));

            // Once authenticated, flush any messages waiting in the persistent outbox
            invoke('flush_outbox').catch(e => console.error("[Network] Flush failed:", e));

            const state = get(userStore) as any;
            Object.keys(state.chats).forEach(peerHash => {
                if (!state.chats[peerHash].isGroup) {
                    logicStore.setOnlineStatus(peerHash, true);
                    logicStore.broadcastProfile(peerHash);
                }
            });
            return;
        }

        if (msg.type === 'error') {
            console.error("Server error:", msg.message);
            if (msg.code === 'auth_failed') {
                console.warn("Authentication failed. Clearing session token.");
                userStore.update((s: any) => ({ ...s, sessionToken: null }));
            }
            return;
        }

        if (msg.type === 'ping') {
            this.sendJSON({ type: 'pong' });
            return;
        }

        if (msg.type === 'queued_message') {
            await logicStore.handleIncomingMessage(msg.payload);
            return;
        }

        await logicStore.handleIncomingMessage(msg);
    }

    sendJSON(data: any) {
        try {
            let msg = JSON.stringify(data);
            invoke('send_to_network', { msg, isBinary: false, metadata: data }).catch(e => {
                if (e.toString().includes("queued")) {
                    console.debug("[Network] Message queued in persistent outbox");
                } else {
                    console.warn("[Network] Background send failed:", e);
                }
            });
        } catch (e) {
            console.error("Native sendJSON failed", e);
        }
    }

    sendBinary(recipientHash: string, data: Uint8Array, metadata?: any) {
        const routingHash = recipientHash.split('.')[0];
        const encoder = new TextEncoder();
        const hashBytes = encoder.encode(routingHash);
        if (hashBytes.length !== 64) return;

        const packet = new Uint8Array(64 + data.length);
        packet.set(hashBytes, 0);
        packet.set(data, 64);

        const hex = Array.from(packet).map(b => b.toString(16).padStart(2, '0')).join('');

        try {
            invoke('send_to_network', { msg: hex, isBinary: true, metadata }).catch(e => {
                if (e.toString().includes("queued")) {
                    console.debug("[Network] Binary queued in persistent outbox");
                } else {
                    console.warn("[Network] Binary background send failed:", e);
                }
            });
        } catch (e) {
            console.error("Native sendBinary failed", e);
        }
    }

    sendVolatile(recipientHash: string, data: Uint8Array) {
        if (!this.isAuthenticated) return;
        const body = new TextDecoder().decode(data);
        this.sendJSON({
            type: 'volatile_relay',
            to: recipientHash,
            body: body
        });
    }

    sendTyping(recipientHash: string, isTyping: boolean) {
        if (!this.isAuthenticated) return;
        this.sendJSON({
            type: 'volatile_relay',
            to: recipientHash,
            body: JSON.stringify({ type: 'typing', isTyping })
        });
    }

    disconnect() {
        this.isConnected = false;
        this.isAuthenticated = false;
        userStore.update(s => ({ ...s, isConnected: false, connectionStatus: 'disconnected' }));
    }
}

export const network = new NetworkLayer();
