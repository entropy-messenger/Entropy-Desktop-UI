
export interface LinkPreview {
    url: string;
    title?: string;
    description?: string;
    siteName?: string;
    image?: string;
}

export interface Message {
    id: string;
    timestamp: number;
    senderHash: string;
    senderAlias?: string;
    content: string;
    type: 'text' | 'voice_note' | 'file' | 'signaling';
    attachment?: {
        url?: string;
        fileName?: string;
        fileType?: string;
        size?: number;
        data?: Uint8Array;
    };
    groupId?: string;
    isMine: boolean;
    status: 'sending' | 'sent' | 'delivered' | 'read' | 'failed';
    pfp?: string;
    isStarred?: boolean;
    replyTo?: {
        id: string;
        content: string;
        senderAlias?: string;
        type: Message['type'];
    };
    linkPreview?: LinkPreview;
}

export interface PrivacySettings {
    readReceipts: boolean;
    lastSeen: 'everyone' | 'nobody';
    profilePhoto: 'everyone' | 'nobody';
    routingMode: 'direct' | 'tor' | 'custom';
    proxyUrl?: string;
}

export interface Chat {
    peerHash: string;
    peerAlias?: string;
    pfp?: string;
    messages: Message[];
    lastSeen?: number;
    unreadCount: number;
    isOnline?: boolean;
    isTyping?: boolean;
    isGroup?: boolean;
    members?: string[];
    isPinned?: boolean;
    isArchived?: boolean;
    isMuted?: boolean;
    isVerified?: boolean;
    disappearingTimer?: number;
    localNickname?: string;
    inviteCode?: string;
}

export interface ServerMessage {
    type: string | number;
    payload?: any;
    [key: string]: any;
}

export interface AuthPayload {
    timestamp: number;
    nonce: number;
    identity_hash: string;
}
