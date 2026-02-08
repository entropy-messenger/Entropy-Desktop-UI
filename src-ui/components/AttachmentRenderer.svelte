
<script lang="ts">
    import { attachmentStore } from '../lib/attachment_store';
    import { LucideMic, LucidePaperclip, LucideDownload, LucideLoader, LucideCheck } from 'lucide-svelte';

    import { markAsDownloaded } from '../lib/actions/message_utils';

    let { msg, chatId } = $props();

    let blobUrl = $state<string | null>(null);
    let loading = $state(false);
    let error = $state(false);
    let isDownloading = $state(false);
    let downloadSuccess = $state(msg.attachment?.isDownloaded || false);

    import VoiceNotePlayer from './VoiceNotePlayer.svelte';
    import { signalManager } from '../lib/signal_manager';
    import { toHex } from '../lib/crypto';
    import { invoke } from '@tauri-apps/api/core';
    import { isPermissionGranted, requestPermission, sendNotification } from '@tauri-apps/plugin-notification';

    async function loadAttachment() {
        if (!msg.attachment) return;
        console.debug("[Attachment] Loading:", msg.id, msg.attachment.fileName);
        
        if (msg.attachment.data) {
            console.debug("[Attachment] Data already present in message object.");
            blobUrl = URL.createObjectURL(new Blob([msg.attachment.data], {type: msg.attachment.fileType}));
            return;
        }

        loading = true;
        try {
            const data = await attachmentStore.get(msg.id);
            if (data) {
                console.debug("[Attachment] Retrieved from store. Size:", data.length);
                if (msg.attachment.isV2 && msg.attachment.bundle) {
                    console.debug("[Attachment] Decrypting V2 media...");
                    const decrypted = await signalManager.decryptMedia(data, msg.attachment.bundle);
                    blobUrl = URL.createObjectURL(new Blob([decrypted as any], {type: msg.attachment.fileType}));
                    console.debug("[Attachment] Created blob URL:", blobUrl);
                } else {
                    blobUrl = URL.createObjectURL(new Blob([data as any], {type: msg.attachment.fileType}));
                    console.debug("[Attachment] Created legacy blob URL:", blobUrl);
                }
            } else {
                console.warn("[Attachment] Not found in attachmentStore:", msg.id);
                error = true;
            }
        } catch (e) {
            console.error("[Attachment] Load error:", e);
            error = true;
        } finally {
            loading = false;
        }
    }

    async function manualDownload() {
        if (isDownloading) return;
        isDownloading = true;
        downloadSuccess = false;

        console.debug("[Attachment] Manual download requested for:", msg.attachment.fileName);
        try {
            // First check if it's already in the message object (V1)
            let bytes: Uint8Array | null = null;
            if (msg.attachment.data) {
                bytes = msg.attachment.data;
            } else {
                const data = await attachmentStore.get(msg.id);
                if (data) {
                    if (msg.attachment.isV2 && msg.attachment.bundle) {
                        bytes = await signalManager.decryptMedia(data, msg.attachment.bundle);
                    } else {
                        bytes = data;
                    }
                }
            }

            if (!bytes) throw new Error("File data not found");

            console.debug("[Attachment] Saving file via native bridge...");
            await invoke('save_file', { 
                data: Array.from(bytes),
                filename: msg.attachment.fileName || 'download' 
            });

            downloadSuccess = true;
            if (chatId) markAsDownloaded(chatId, msg.id);

            // Notify user
            let hasPermission = await isPermissionGranted();
            if (!hasPermission) {
                const permission = await requestPermission();
                hasPermission = permission === 'granted';
            }
            if (hasPermission) {
                sendNotification({ 
                    title: 'Download Complete', 
                    body: `Saved ${msg.attachment.fileName} to Downloads` 
                });
            }
        } catch (e: any) {
            console.error("[Attachment] Native save failed:", e);
        } finally {
            isDownloading = false;
        }
    }

    $effect(() => {
        loadAttachment();
        return () => {
            if (blobUrl) {
                console.debug("[Attachment] Revoking blob URL:", blobUrl);
                URL.revokeObjectURL(blobUrl);
            }
        };
    });
</script>

{#if msg.type === 'voice_note'}
    {#if blobUrl}
        <VoiceNotePlayer src={blobUrl} id={msg.id} isMine={msg.isMine} />
    {:else if loading}
        <div class="flex items-center space-x-2 py-2 px-4 bg-black/5 rounded-2xl">
            <LucideLoader size={16} class="animate-spin text-gray-400" />
            <span class="text-[10px] font-bold text-gray-400 uppercase tracking-widest">Loading Voice Note...</span>
        </div>
    {:else if msg.status === 'sending'}
        <div class="flex items-center space-x-2 py-2 px-4 bg-blue-50/50 rounded-2xl animate-pulse">
            <LucideLoader size={16} class="animate-spin text-blue-400" />
            <span class="text-[10px] font-black text-blue-400 uppercase tracking-widest">Sending...</span>
        </div>
    {:else}
        <div class="flex items-center space-x-2 py-2 px-4 bg-red-50 rounded-2xl">
            <LucideMic size={16} class="text-red-400" />
            <span class="text-[10px] font-bold text-red-400 uppercase tracking-widest">Error loading audio</span>
        </div>
    {/if}
{:else if msg.type === 'file'}
    <div class="flex flex-col space-y-2">
        {#if msg.attachment.fileType?.startsWith('image/') && blobUrl}
            <div class="relative group max-w-sm rounded-lg overflow-hidden border border-black/10 shadow-sm bg-gray-100">
                <img 
                    src={blobUrl} 
                    alt={msg.attachment.fileName} 
                    class="max-h-64 object-contain mx-auto"
                />
                <div class="absolute inset-0 bg-black/40 opacity-0 group-hover:opacity-100 transition-opacity flex items-center justify-center">
                    <button 
                        onclick={manualDownload}
                        class="p-2 bg-white rounded-full text-black hover:scale-110 transition shadow-lg disabled:opacity-80 disabled:cursor-wait"
                        title={downloadSuccess ? 'Downloaded' : 'Download Image'}
                        disabled={isDownloading || downloadSuccess}
                    >
                        {#if isDownloading}
                            <LucideLoader size={20} class="animate-spin text-blue-500" />
                        {:else if downloadSuccess}
                            <LucideCheck size={20} class="text-green-500" />
                        {:else}
                            <LucideDownload size={20} />
                        {/if}
                    </button>
                </div>
            </div>
        {/if}

        <div class="flex items-center space-x-3 bg-white/40 backdrop-blur-sm p-3 rounded-2xl border border-black/5 shadow-sm group/file hover:bg-white/60 transition-colors">
            <div class="w-10 h-10 rounded-xl bg-blue-500/10 flex items-center justify-center text-blue-600 shrink-0">
                <LucidePaperclip size={20} />
            </div>
            <div class="flex-1 min-w-0">
                <div class="text-[11px] font-black truncate text-gray-800 uppercase tracking-tight">{msg.attachment.fileName}</div>
                <div class="text-[9px] font-bold text-gray-400 uppercase tracking-widest">
                    {(msg.attachment.size || 0) / 1024 > 1024 
                        ? ((msg.attachment.size || 0)/1024/1024).toFixed(1) + ' MB' 
                        : ((msg.attachment.size || 0)/1024).toFixed(1) + ' KB'}
                </div>
            </div>
            {#if blobUrl}
                <button 
                    onclick={manualDownload}
                    class="w-8 h-8 rounded-lg {downloadSuccess ? 'bg-green-500' : 'bg-blue-600'} text-white flex items-center justify-center hover:bg-opacity-90 transition shadow-md active:scale-95 disabled:opacity-70 disabled:cursor-wait"
                    title={downloadSuccess ? 'Downloaded' : 'Download File'}
                    disabled={isDownloading || downloadSuccess}
                >
                    {#if isDownloading}
                        <LucideLoader size={14} class="animate-spin" />
                    {:else if downloadSuccess}
                        <LucideCheck size={14} />
                    {:else}
                        <LucideDownload size={14} />
                    {/if}
                </button>
            {:else if loading}
                <div class="w-8 h-8 flex items-center justify-center">
                    <LucideLoader size={16} class="animate-spin text-blue-500" />
                </div>
            {:else if msg.status === 'sending'}
                <div class="w-8 h-8 flex items-center justify-center">
                    <LucideLoader size={16} class="animate-spin text-blue-500" />
                </div>
            {:else}
                <button onclick={loadAttachment} class="w-8 h-8 rounded-lg bg-red-50 text-red-500 flex items-center justify-center hover:bg-red-100 italic transition font-black text-[9px]">!</button>
            {/if}
        </div>
    </div>
{/if}
