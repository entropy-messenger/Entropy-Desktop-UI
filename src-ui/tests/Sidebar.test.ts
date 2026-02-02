
import { render, fireEvent, screen, waitFor } from '@testing-library/svelte';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import Sidebar from '../components/Sidebar.svelte';
import { userStore } from '../lib/stores/user';
import { startChat, createGroup } from '../lib/store';
import { get } from 'svelte/store';

// Mock dependencies
vi.mock('../lib/store', () => ({
    startChat: vi.fn(),
    createGroup: vi.fn(),
    updateMyProfile: vi.fn(),
    togglePin: vi.fn(),
    toggleArchive: vi.fn(),
    toggleMute: vi.fn(),
    toggleBlock: vi.fn(),
    updatePrivacy: vi.fn(),
    registerGlobalNickname: vi.fn().mockResolvedValue({ success: true }),
    lookupNickname: vi.fn(),
    burnAccount: vi.fn(),
    refreshDecoys: vi.fn()
}));

// Mock removed to use actual components or rely on default behavior

describe('Sidebar Component', () => {
    beforeEach(() => {
        userStore.set({
            identityHash: 'my-hash',
            myAlias: 'Me',
            myPfp: null,
            chats: {
                'peer1': {
                    peerHash: 'peer1',
                    peerAlias: 'Alice',
                    messages: [{ content: 'Hi', timestamp: 1000, isMine: false, id: '1', type: 'text', senderHash: 'peer1', status: 'read' }],
                    unreadCount: 1,
                    isPinned: false,
                    isArchived: false,
                    isMuted: false,
                    isVerified: false,
                    isGroup: false,
                    isTyping: false
                }
            },
            blockedHashes: [],
            activeChatHash: null,
            isConnected: true,
            searchQuery: '',
            replyingTo: null,
            privacySettings: {} as any,
            sessionToken: null,
            myGlobalNickname: null,
            nicknameExpiry: null,
            connectionStatus: 'connected',
            authError: null,
            keysMissing: false,
            relayUrl: ''
        });
    });

    it('renders chat list correctly', () => {
        render(Sidebar);
        expect(screen.getByText('Alice')).toBeTruthy();
        expect(screen.getByText('Hi')).toBeTruthy();
        expect(screen.getByText('1')).toBeTruthy(); // Unread count
    });

    it('selects chat on click', async () => {
        const { component } = render(Sidebar);
        // "Alice" might appear in multiple places (name, message content, etc.)
        // We specifficaly want the one in the chat list item.
        const matches = screen.getAllByText('Alice');
        const chatItem = matches[0].closest('div[role="button"]');
        expect(chatItem).toBeTruthy();

        await fireEvent.click(chatItem!);

        expect(startChat).toHaveBeenCalledWith('peer1');
    });

    it('opens settings panel', async () => {
        render(Sidebar);
        const settingsBtn = document.querySelector('button[title="New Message"]')?.nextElementSibling;

        // We need to click the settings button.
        // It's the 3rd button in the header group.
        const buttons = document.querySelectorAll('.flex.items-center.space-x-1 button');
        await fireEvent.click(buttons[2]); // The settings button

        expect(screen.getAllByText('Settings')[0]).toBeTruthy(); // Might accept H1 or label
        expect(screen.getByText('Profile')).toBeTruthy();
    });


});
