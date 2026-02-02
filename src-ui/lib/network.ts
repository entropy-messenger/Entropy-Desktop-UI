import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import type { ServerMessage } from './types';

export class NetworkLayer {
    private url: string = "";
    private retryCount = 0;
    private maxRetries = 5;
    private isAuthenticated = false;
    private messageQueue: { type: 'json' | 'binary'; data: any; recipient?: string; isVolatile?: boolean }[] = [];
    private heartbeatInterval: any;
    private isConnected = false;


    private userStoreModule: any = null;
    private logicStoreModule: any = null;

    constructor() {
        import('./stores/user').then(m => this.userStoreModule = m);
        import('./store').then(m => this.logicStoreModule = m);


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

    async connect() {
        if (this.isConnected) return;

        const { get } = await import('svelte/store');
        if (this.userStoreModule) {
            const state = get(this.userStoreModule.userStore) as any;
            this.url = state.relayUrl.replace('http', 'ws') + '/ws';
            const bearerToken = state.sessionToken;

            let proxyUrl = undefined;
            if (state.privacySettings.routingMode !== 'direct') {
                proxyUrl = state.privacySettings.proxyUrl;
                if (state.privacySettings.routingMode === 'tor') {
                    proxyUrl = 'socks5://127.0.0.1:9050';
                }
            }

            console.log(`Commanding native connection to ${this.url} (Proxy: ${proxyUrl || 'none'})...`);
            try {
                await invoke('connect_network', { relayUrl: this.url, bearerToken, proxyUrl });
                this.isConnected = true;
                this.onConnect();
            } catch (e) {
                console.error("Native connection failed:", e);
                this.retry();
            }
        }
    }

    private stabilityTimer: any = null;

    private onConnect() {
        console.log('Native network layer connected');



        if (this.stabilityTimer) clearTimeout(this.stabilityTimer);
        this.stabilityTimer = setTimeout(() => {
            console.log("Connection stabilized. Resetting retry count.");
            this.retryCount = 0;
        }, 5000);

        if (this.userStoreModule) {
            this.userStoreModule.userStore.update((s: any) => ({ ...s, isConnected: true }));

            if (this.logicStoreModule) {
                import('svelte/store').then(({ get }) => {
                    const state = get(this.userStoreModule.userStore) as any;
                    if (state.identityHash) {
                        this.logicStoreModule.authenticate(state.identityHash);
                    }
                });
            }
        }
        this.startHeartbeat();
    }

    private onDisconnect() {
        console.log('Native network layer disconnected');


        if (this.stabilityTimer) {
            clearTimeout(this.stabilityTimer);
            this.stabilityTimer = null;
        }

        this.isConnected = false;
        this.isAuthenticated = false;
        this.stopHeartbeat();

        if (this.userStoreModule) {
            this.userStoreModule.userStore.update((s: any) => ({
                ...s,
                isConnected: false,
                connectionStatus: 'disconnected'
            }));
        }
        this.retry();
    }

    private retry() {
        if (this.retryCount < this.maxRetries) {
            this.retryCount++;
            setTimeout(() => this.connect(), 2000 * this.retryCount);
        }
    }

    private startHeartbeat() {
        this.stopHeartbeat();


        this.heartbeatInterval = setInterval(() => {
            if (!this.isConnected) return;


            if (this.messageQueue.length > 0) {
                const item = this.messageQueue.shift();
                if (item) {
                    if (item.type === 'json') {
                        this.executeSendJSON(item.data);
                    } else if (item.type === 'binary' && item.recipient) {
                        this.executeSendBinary(item.recipient, item.data);
                    }
                }
            } else {
                this.executeSendJSON({ type: 'dummy', ts: Date.now() });
            }
        }, 500);
    }

    private stopHeartbeat() {
        if (this.heartbeatInterval) {
            clearInterval(this.heartbeatInterval);
            this.heartbeatInterval = null;
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
        if (this.logicStoreModule) {
            await this.logicStoreModule.handleIncomingMessage(payload);
        }
    }

    private async onJsonMessage(msg: any) {
        if (msg.type === 'auth_success') {
            const token = msg.session_token;
            const id = msg.identity_hash;
            console.log("Authenticated as:", id);
            this.isAuthenticated = true;

            if (this.userStoreModule) {
                this.userStoreModule.userStore.update((s: any) => ({
                    ...s,
                    sessionToken: token || s.sessionToken,
                    connectionStatus: token ? 'connected' : s.connectionStatus,
                    keysMissing: !!msg.keys_missing
                }));
            }
            if (this.logicStoreModule && this.logicStoreModule.resetAuthStatus) {
                this.logicStoreModule.resetAuthStatus();
            }
            return;
        }

        if (msg.type === 'error') {
            console.error("Server error:", msg.message);
            if (msg.code === 'auth_failed') {
                console.warn("Authentication failed (Token probably expired). Clearing session and re-mining...");
                if (this.userStoreModule) {
                    this.userStoreModule.userStore.update((s: any) => ({ ...s, sessionToken: null, connectionStatus: 'mining' }));
                    if (this.logicStoreModule) {
                        this.logicStoreModule.resetAuthStatus();
                        import('svelte/store').then(({ get }) => {
                            const state = get(this.userStoreModule.userStore) as any;
                            if (state.identityHash) {
                                this.logicStoreModule.authenticate(state.identityHash);
                            }
                        });
                    }
                }
            }
            return;
        }

        if (msg.type === 'ping') {
            this.executeSendJSON({ type: 'pong' });
            return;
        }

        if (msg.type === 'queued_message') {
            if (this.logicStoreModule) await this.logicStoreModule.handleIncomingMessage(msg.payload);
            return;
        }

        if (this.logicStoreModule) await this.logicStoreModule.handleIncomingMessage(msg);
    }

    private flushQueue() {
        let sentCount = 0;
        while (this.messageQueue.length > 0 && sentCount < 10) {
            const item = this.messageQueue.shift();
            if (item) {
                if (item.type === 'json') {
                    this.executeSendJSON(item.data);
                } else if (item.type === 'binary' && item.recipient) {
                    this.executeSendBinary(item.recipient, item.data);
                }
            }
            sentCount++;
        }
    }

    sendJSON(data: any) {
        if (data.type === 'auth' || data.type === 'ping') {
            this.executeSendJSON(data);
            return;
        }
        this.messageQueue.push({ type: 'json', data });
    }

    private async executeSendJSON(data: any) {
        if (!this.isConnected) return;
        try {
            await invoke('send_to_network', { payload: JSON.stringify(data), isBinary: false });
        } catch (e) {
            console.error("Native sendJSON failed", e);
        }
    }

    sendBinary(recipientHash: string, data: Uint8Array) {
        this.messageQueue.push({ type: 'binary', data, recipient: recipientHash });
    }

    private async executeSendBinary(recipientHash: string, data: Uint8Array) {
        if (!this.isConnected) return;

        const routingHash = recipientHash.split('.')[0];
        const encoder = new TextEncoder();
        const hashBytes = encoder.encode(routingHash);
        if (hashBytes.length !== 64) return;

        const packet = new Uint8Array(64 + data.length);
        packet.set(hashBytes, 0);
        packet.set(data, 64);


        const hex = Array.from(packet).map(b => b.toString(16).padStart(2, '0')).join('');

        try {
            await invoke('send_to_network', { payload: hex, isBinary: true });
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
        this.stopHeartbeat();
        this.isConnected = false;
        this.isAuthenticated = false;
    }
}

export const network = new NetworkLayer();
