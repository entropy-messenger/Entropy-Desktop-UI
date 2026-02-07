
export { userStore } from './stores/user';
export type { AppState } from './stores/user';
export * from './actions/auth';
export * from './actions/messaging';
export * from './actions/message_utils';
export * from './actions/contacts';
export * from './actions/groups';
export * from './utils';

// Re-export types if needed by consumers of store.ts
export * from './types';

import { userStore } from './stores/user';
import { vaultSave } from './secure_storage';

// -----------------------------------------------------------------------------
// Subscriptions & Background Logic
// -----------------------------------------------------------------------------

// 2. Persistence (Auto-save) with improved debounce/queueing
let saveTimeout: any = null;

async function performSave(state: any) {
    if (!state.identityHash) return;
    try {
        // Deep copy to remove transient fields and avoid mutation issues during save
        const chatsCopy: any = JSON.parse(JSON.stringify(state.chats));
        for (const h in chatsCopy) {
            delete chatsCopy[h].isOnline;
            delete chatsCopy[h].isTyping;
            for (const m of chatsCopy[h].messages) {
                if (m.attachment?.data) delete m.attachment.data;
            }
        }

        const vault = {
            chats: chatsCopy,
            myAlias: state.myAlias,
            myPfp: state.myPfp,
            blockedHashes: state.blockedHashes,
            privacySettings: state.privacySettings,
            sessionToken: state.sessionToken
        };

        await vaultSave(`entropy_chats_${state.identityHash}`, JSON.stringify(vault));
        console.debug("[Persistence] Saved state successfully.");
    } catch (e) {
        console.error("[Persistence] Failed to persist vault:", e);
    }
}

userStore.subscribe(state => {
    if (!state.identityHash) return;

    if (saveTimeout) clearTimeout(saveTimeout);
    saveTimeout = setTimeout(() => {
        performSave(state);
    }, 1000); // 1s debounce is enough
});
