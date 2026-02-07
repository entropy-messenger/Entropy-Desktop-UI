
<script lang="ts">
  import { userStore } from '../lib/stores/user';
  import { 
    sendMessage, sendFile, sendVoiceNote, 
    sendTypingStatus, setLocalNickname, toggleStar, 
    setDisappearingTimer, setReplyingTo,
    bulkDelete, bulkStar, toggleBlock, toggleVerification 
  } from '../lib/store';
  import { signalManager } from '../lib/signal_manager';
  import { 
    LucideSend, LucideMoreVertical, LucideMic, LucidePaperclip, 
    LucideX, LucideSearch, 
    LucideCheck, LucideCheckCheck, LucideEdit2, LucideUsers,
    LucideStar, LucideReply, LucideClock, LucideBellOff, LucideTrash2,
    LucideExternalLink, LucideImage, LucideLink, LucideFile, LucideInfo,
    LucideCopy, LucideCheck as LucideCheckIcon, LucideShare2, LucideBan,
    LucideShieldCheck, LucideShieldAlert, LucideSquare, LucideTrash
  } from 'lucide-svelte';
  import AttachmentRenderer from './AttachmentRenderer.svelte';
  import VoiceNotePlayer from './VoiceNotePlayer.svelte';
  import { onMount, tick } from 'svelte';
  import { invoke } from '@tauri-apps/api/core';
  import { listen } from '@tauri-apps/api/event';
  import { playingVoiceNoteId } from '../lib/stores/audio';
  
  let messageInput = $state("");
  let fileInput = $state<HTMLInputElement | null>(null);
  let messageSearchQuery = $state("");
  let showMessageSearch = $state(false);
  let scrollContainer = $state<HTMLElement | null>(null);
  let showOptions = $state(false);
  let showGallery = $state(false);

  let selectionMode = $state(false);
  let selectedIds = $state<string[]>([]);
  
  let isRecording = $state(false);
  let recordedBlob = $state<Blob | null>(null);
  let previewUrl = $state<string | null>(null);
  let recordingSeconds = $state(0);
  let recordingInterval: any = null;
  let messageInputEl = $state<HTMLTextAreaElement | null>(null);
  let visualizerCanvas = $state<HTMLCanvasElement | null>(null);
  let volumeUnlisten: (() => void) | null = null;
  let currentVolume = $state(0);

  $effect(() => {
    if (messageInput !== undefined && messageInputEl) {
        messageInputEl.style.height = 'auto';
        messageInputEl.style.height = Math.min(messageInputEl.scrollHeight, 200) + 'px';
    }
  });

  let activeChat = $derived($userStore.activeChatHash ? $userStore.chats[$userStore.activeChatHash] : null);
  let replyingTo = $derived($userStore.replyingTo);
  
  const scrollToBottom = async () => {
      await tick();
      if (scrollContainer && !selectionMode) scrollContainer.scrollTop = scrollContainer.scrollHeight;
  };

  $effect(() => {
    if (activeChat?.messages) {
      scrollToBottom();
    }
  });

  const handleSend = () => {
    if (!messageInput.trim() || !activeChat) return;
    const dest = activeChat.peerHash;
    sendMessage(dest, messageInput);
    messageInput = "";
    isLocallyTyping = false;
    sendTypingStatus(dest, false).catch(() => {});
  };
  
  const handleKeydown = (e: KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        handleSend();
    }
  };

  const onFileSelect = (e: Event) => {
    const files = (e.target as HTMLInputElement).files;
    if (files && files.length > 0 && activeChat) sendFile(activeChat.peerHash, files[0]);
  };

  const startRecording = async () => {
    try {
        await invoke('start_native_recording');
        
        isRecording = true;
        recordingSeconds = 0;
        recordedBlob = null;
        if (previewUrl) URL.revokeObjectURL(previewUrl);
        previewUrl = null;

        // Setup Visualizer listener
        if (volumeUnlisten) volumeUnlisten();
        volumeUnlisten = await listen<number>('recording-volume', (event) => {
            currentVolume = event.payload;
            drawNativeWaveform();
        });

        recordingInterval = setInterval(() => { recordingSeconds++; }, 1000);
    } catch (e: any) { 
        console.error("Recording error:", e); 
        alert("Microphone error: " + e);
    }
  };

  const drawNativeWaveform = () => {
      if (!visualizerCanvas) return;
      const ctx = visualizerCanvas.getContext('2d');
      if (!ctx) return;
      
      const width = visualizerCanvas.width;
      const height = visualizerCanvas.height;
      // Fade out effect
      ctx.fillStyle = 'rgba(255, 255, 255, 0.2)';
      ctx.fillRect(0, 0, width, height);
      
      const bars = 40;
      const barWidth = width / bars;
      // Shift canvas to the left
      const imageData = ctx.getImageData(barWidth, 0, width - barWidth, height);
      ctx.putImageData(imageData, 0, 0);
      ctx.clearRect(width - barWidth, 0, barWidth, height);

      // Draw new bar at the end
      const barHeight = Math.max(2, currentVolume * height * 4);
      ctx.fillStyle = '#ef4444';
      ctx.beginPath();
      ctx.roundRect(width - barWidth + 1, (height - barHeight) / 2, barWidth - 2, barHeight, 1);
      ctx.fill();
  };

  const stopRecording = async () => {
      if (isRecording) {
          try {
              const bytes = await invoke<number[]>('stop_native_recording');
              recordedBlob = new Blob([new Uint8Array(bytes)], { type: 'audio/wav' });
              previewUrl = URL.createObjectURL(recordedBlob);
              
              isRecording = false;
              if (recordingInterval) clearInterval(recordingInterval);
              if (volumeUnlisten) {
                  volumeUnlisten();
                  volumeUnlisten = null;
              }
          } catch (e) {
              console.error("Stop recording error:", e);
          }
      }
  };

  const cancelRecording = async () => {
      if (isRecording) {
          await invoke('stop_native_recording');
      }
      isRecording = false;
      if (recordingInterval) clearInterval(recordingInterval);
      if (volumeUnlisten) {
          volumeUnlisten();
          volumeUnlisten = null;
      }
      recordedBlob = null;
      if (previewUrl) URL.revokeObjectURL(previewUrl);
      previewUrl = null;
      recordingSeconds = 0;
  };

  const sendRecordedVoiceNote = () => {
      if (recordedBlob && activeChat) {
          sendVoiceNote(activeChat.peerHash, recordedBlob);
          cancelRecording();
      }
  };

  const formatRecordingTime = (s: number) => {
      const mins = Math.floor(s / 60);
      const secs = s % 60;
      return `${mins}:${secs.toString().padStart(2, '0')}`;
  };

  const setDisappearing = () => {
      if (!activeChat) return;
      const val = prompt("Set disappearing messages timer (seconds, 0 to disable):", (activeChat.disappearingTimer || 0).toString());
      if (val !== null) setDisappearingTimer(activeChat.peerHash, parseInt(val) || null);
  };

  const handleSetLocalNickname = () => {
      if (!activeChat) return;
      const val = prompt("Set a local nickname for this contact:", activeChat.localNickname || activeChat.peerAlias || "");
      if (val !== null) setLocalNickname(activeChat.peerHash, val.trim() || null);
  };

  const scrollToMessage = (id: string) => {
      const el = document.getElementById(`msg-${id}`);
      if (el) el.scrollIntoView({ behavior: 'smooth', block: 'center' });
  };
  
  const toggleSelect = (id: string) => {
      if (!selectionMode) { selectionMode = true; selectedIds = [id]; return; }
      if (selectedIds.includes(id)) {
          selectedIds = selectedIds.filter(x => x !== id);
          if (selectedIds.length === 0) selectionMode = false;
      } else {
          selectedIds = [...selectedIds, id];
      }
  };

  const cancelSelection = () => { selectionMode = false; selectedIds = []; };
  
  const handleBulkStar = () => { if (activeChat) { bulkStar(activeChat.peerHash, selectedIds); cancelSelection(); } };
  const handleBulkDelete = () => { 
    if (activeChat && confirm(`Delete ${selectedIds.length} messages?`)) { 
        bulkDelete(activeChat.peerHash, selectedIds); cancelSelection(); 
    } 
  };
  
  let mediaMessages = $derived(activeChat ? activeChat.messages.filter((m: any) => m.type === 'file' || m.type === 'voice_note') : []);
  let linkMessages = $derived(activeChat ? activeChat.messages.filter((m: any) => m.linkPreview) : []);

  let inviteCopied = $state(false);
  const copyInvite = () => {
      if (!activeChat) return;
      const link = `entropy://${activeChat.peerHash}`;
      navigator.clipboard.writeText(link);
      inviteCopied = true;
      setTimeout(() => inviteCopied = false, 2000);
  };
  
  let typingTimeout: any;
  let isLocallyTyping = false;
  let lastTypingSent = 0;
  let lastTypingPeer: string | null = null;

  $effect(() => {
      // Track input and chat changes
      const currentInput = messageInput;
      const currentPeer = activeChat?.peerHash;
      
      // Handle chat switch
      if (lastTypingPeer && lastTypingPeer !== currentPeer) {
          if (isLocallyTyping) {
              sendTypingStatus(lastTypingPeer, false).catch(() => {});
              isLocallyTyping = false;
          }
      }
      lastTypingPeer = currentPeer;

      if (currentInput.length > 0 && activeChat && !activeChat.isGroup) {
          const now = Date.now();
          // Send if first time or every 4s to keep recipient timer alive
          if (!isLocallyTyping || (now - lastTypingSent > 4000)) {
              isLocallyTyping = true;
              lastTypingSent = now;
              sendTypingStatus(activeChat.peerHash, true).catch(() => {});
          }
      } else if (currentInput.length === 0 && isLocallyTyping && activeChat && !activeChat.isGroup) {
          isLocallyTyping = false;
          sendTypingStatus(activeChat.peerHash, false).catch(() => {});
      }
      
      if (typingTimeout) clearTimeout(typingTimeout);
      if (activeChat && !activeChat.isGroup) {
          const typingPeer = activeChat.peerHash;
          typingTimeout = setTimeout(() => {
              if (isLocallyTyping) {
                  isLocallyTyping = false;
                  sendTypingStatus(typingPeer, false).catch(() => {});
              }
          }, 2000);
      }

      return () => {
          if (typingTimeout) clearTimeout(typingTimeout);
      };
  });
</script>

{#if !activeChat}
    <div class="h-full w-full flex items-center justify-center bg-[#f0f2f5] flex-col text-center p-8">
        <div class="w-20 h-20 bg-white rounded-3xl flex items-center justify-center mb-6 shadow-xl border border-black/5 animate-bounce-subtle">
            <img src="/logo.png" alt="logo" class="w-16 h-16 object-contain" />
        </div>
        <h2 class="text-2xl font-black text-gray-900 mb-2 tracking-tighter uppercase">Entropy</h2>
        <p class="text-gray-500 max-w-sm font-bold text-[10px] leading-relaxed opacity-40 uppercase tracking-widest pl-1">Select a conversation to start messaging.<br>Secure P2P Messaging.</p>
    </div>
{:else}
    <div class="h-full w-full flex bg-[#efeae2] relative overflow-hidden">
        <div class="flex-1 flex flex-col relative h-full min-w-0">
            <div class="bg-white/95 backdrop-blur-md p-3 px-4 border-b border-gray-200 flex justify-between items-center shadow-sm z-30">
                <div class="flex items-center space-x-3 overflow-hidden cursor-pointer" onclick={() => showGallery = !showGallery} onkeypress={(e) => e.key === 'Enter' && (showGallery = !showGallery)} role="button" tabindex="0">
                    <div class="w-10 h-10 rounded-xl bg-gradient-to-tr {activeChat.isGroup ? 'from-purple-500 to-indigo-600' : 'from-blue-400 to-blue-600'} shrink-0 flex items-center justify-center text-white font-bold shadow-sm relative overflow-hidden">
                        {#if activeChat.pfp}
                            <img src={activeChat.pfp} alt="" class="w-full h-full object-cover" />
                        {:else}
                            {activeChat.peerAlias ? activeChat.peerAlias[0].toUpperCase() : '?'}
                        {/if}
                    </div>
                    <div class="min-w-0">
                        <div class="flex items-center space-x-2">
                            <div class="font-bold text-gray-800 leading-tight truncate">
                                {activeChat.localNickname || activeChat.peerAlias || activeChat.peerHash.slice(0, 12)}
                            </div>
                            {#if activeChat.isVerified}
                                <LucideShieldCheck size={14} class="text-green-500" />
                            {/if}
                            {#if activeChat.isMuted}<LucideBellOff size={11} class="text-gray-400" />{/if}
                        </div>
                        <div class="text-[10px] font-bold h-3 truncate uppercase tracking-tight {activeChat.isTyping ? 'text-blue-500 animate-pulse' : 'opacity-50'}">
                            {activeChat.isTyping ? "typing..." : (activeChat.isOnline ? "online" : "offline")}
                        </div>
                    </div>
                </div>

                <div class="flex items-center space-x-1">
                    {#if selectionMode}
                        <div class="flex items-center bg-blue-50 px-3 py-1 rounded-full mr-2">
                            <span class="text-xs font-black text-blue-600 mr-4">{selectedIds.length} SELECTED</span>
                            <button onclick={handleBulkStar} class="p-2 text-blue-600 hover:bg-blue-100 rounded-full transition"><LucideStar size={18} /></button>
                            <button onclick={handleBulkDelete} class="p-2 text-red-600 hover:bg-red-100 rounded-full transition"><LucideTrash2 size={18} /></button>
                            <button onclick={cancelSelection} class="p-2 text-gray-500 hover:bg-gray-200 rounded-full transition ml-1"><LucideX size={18} /></button>
                        </div>
                    {:else}
                        <button onclick={() => showMessageSearch = !showMessageSearch} class="p-2 {showMessageSearch ? 'text-blue-500 bg-blue-50' : 'text-gray-400'} hover:text-blue-500 hover:bg-gray-100 rounded-full transition"><LucideSearch size={20} /></button>
                        <div class="relative">
                            <button onclick={() => showOptions = !showOptions} class="p-2 text-gray-400 hover:text-blue-500 hover:bg-gray-100 rounded-full transition"><LucideMoreVertical size={20} /></button>
                            {#if showOptions}
                                <div class="absolute right-0 mt-2 w-56 bg-white rounded-xl shadow-2xl border border-gray-100 py-2 z-[100] animate-in fade-in zoom-in-95 duration-150" onclick={() => showOptions = false} onkeypress={(e) => e.key === 'Enter' && (showOptions = false)} role="button" tabindex="0">
                                    <button onclick={() => {showGallery = true; showOptions = false;}} class="w-full text-left px-4 py-2 text-sm text-gray-700 hover:bg-gray-50 flex items-center space-x-3"><LucideInfo size={16} /> <span>Contact Info</span></button>
                                    <button onclick={() => {handleSetLocalNickname(); showOptions = false;}} class="w-full text-left px-4 py-2 text-sm text-gray-700 hover:bg-gray-50 flex items-center space-x-3"><LucideEdit2 size={16} /> <span>Set Nickname</span></button>
                                    <button onclick={() => {selectionMode = true; showOptions = false;}} class="w-full text-left px-4 py-2 text-sm text-gray-700 hover:bg-gray-50 flex items-center space-x-3"><LucideCheckIcon size={16} /> <span>Select Messages</span></button>
                                    <button onclick={() => {setDisappearing(); showOptions = false;}} class="w-full text-left px-4 py-2 text-sm text-gray-700 hover:bg-gray-50 flex items-center space-x-3"><LucideClock size={16} /> <span>Disappearing Messages</span></button>
                                    <div class="h-px bg-gray-100 my-1"></div>
                                    {#if !activeChat.isGroup}
                                        <button onclick={() => {toggleBlock(activeChat.peerHash); showOptions = false;}} class="w-full text-left px-4 py-2 text-sm text-red-600 hover:bg-red-50 flex items-center space-x-3">
                                            <LucideBan size={16} /> <span>{$userStore.blockedHashes.includes(activeChat.peerHash) ? 'Unblock Contact' : 'Block Contact'}</span>
                                        </button>
                                    {/if}
                                </div>
                            {/if}
                        </div>
                    {/if}
                </div>
            </div>
            
            {#if $playingVoiceNoteId}
                <div class="bg-blue-600 text-white p-1.5 px-4 flex items-center justify-between animate-in slide-in-from-top duration-300 z-20">
                    <div class="flex items-center space-x-2">
                        <div class="flex space-x-0.5">
                            <div class="w-1 h-3 bg-white/40 animate-pulse delay-75"></div>
                            <div class="w-1 h-3 bg-white/40 animate-pulse delay-150"></div>
                            <div class="w-1 h-3 bg-white/40 animate-pulse delay-300"></div>
                        </div>
                        <span class="text-[10px] font-black uppercase tracking-widest">Listening to Voice Note</span>
                    </div>
                    <button onclick={() => playingVoiceNoteId.set(null)} class="text-[9px] font-black uppercase tracking-tighter hover:underline bg-white/10 px-2 py-0.5 rounded-md">Stop</button>
                </div>
            {/if}

            {#if showMessageSearch}
                <div class="bg-white/95 backdrop-blur-md p-2 px-4 border-b border-gray-200 animate-in slide-in-from-top duration-200 z-20">
                    <div class="relative">
                        <LucideSearch size={14} class="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400" />
                        <input 
                            type="text" 
                            bind:value={messageSearchQuery}
                            placeholder="Search in this conversation..." 
                            class="w-full pl-9 pr-10 py-2 bg-gray-100 border-none rounded-xl text-xs focus:ring-1 focus:ring-blue-500/50 transition whitespace-pre"
                        />
                        {#if messageSearchQuery}
                            <button onclick={() => messageSearchQuery = ""} class="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600">
                                <LucideX size={14} />
                            </button>
                        {/if}
                    </div>
                </div>
            {/if}
            
            <div bind:this={scrollContainer} class="flex-1 overflow-y-auto p-4 space-y-3 custom-scrollbar bg-[#f0f2f5]/30">
                {#if activeChat.disappearingTimer}
                    <div class="flex justify-center mb-4">
                        <div class="bg-blue-600/10 border border-blue-500/20 px-4 py-1.5 rounded-full flex items-center space-x-2 text-[10px] font-black uppercase tracking-widest text-blue-600 shadow-sm">
                            <LucideClock size={12} />
                            <span>Disappearing Messages: {activeChat.disappearingTimer}s</span>
                        </div>
                    </div>
                {/if}
                {#each activeChat.messages.filter(m => !messageSearchQuery || m.content.toLowerCase().includes(messageSearchQuery.toLowerCase())) as msg (msg.id)}
                    <div id="msg-{msg.id}" class="flex {msg.isMine ? 'justify-end' : 'justify-start'} group items-center">
                        {#if selectionMode}
                            <div class="mr-4 order-first">
                                <button 
                                    onclick={() => toggleSelect(msg.id)}
                                    class="w-5 h-5 rounded-full border-2 transition-all flex items-center justify-center {selectedIds.includes(msg.id) ? 'bg-blue-600 border-blue-600' : 'border-gray-300 bg-white'}"
                                >
                                    {#if selectedIds.includes(msg.id)}<LucideCheckIcon size={12} class="text-white" />{/if}
                                </button>
                            </div>
                        {/if}

                        <div class="flex flex-col {msg.isMine ? 'items-end' : 'items-start'} max-w-[65%]">
                            <div 
                                class="relative rounded-2xl shadow-sm transition-all duration-200 overflow-hidden
                                    {msg.type === 'voice_note' ? 'p-1.5 px-2' : 'p-2.5 px-4'}
                                    {msg.isMine ? 'bg-[#dcf8c6] text-gray-800 rounded-tr-none' : 'bg-white text-gray-800 rounded-tl-none'}
                                    {msg.isStarred ? 'ring-2 ring-yellow-400/30' : ''}
                                    {selectedIds.includes(msg.id) ? 'opacity-50 scale-95' : ''}
                                "
                                style="word-break: break-all;"
                                ondblclick={() => toggleSelect(msg.id)}
                                role="button"
                                tabindex="0"
                            >
                                {#if msg.replyTo}
                                    <div onclick={() => scrollToMessage(msg.replyTo!.id)} onkeypress={(e) => e.key === 'Enter' && scrollToMessage(msg.replyTo!.id)} role="button" tabindex="0" class="bg-black/5 p-2 rounded-lg border-l-4 border-blue-500 mb-2 cursor-pointer hover:bg-black/10 transition overflow-hidden">
                                        <div class="text-[10px] font-black text-blue-600 truncate">{msg.replyTo.senderAlias || 'Peer'}</div>
                                        <div class="text-xs text-gray-600 truncate opacity-80">{msg.replyTo.content}</div>
                                    </div>
                                {/if}

                                {#if activeChat.isGroup && !msg.isMine}
                                    <div class="text-[10px] font-black text-blue-600 mb-1 opacity-80 uppercase tracking-wider">{msg.senderAlias || msg.senderHash.slice(0, 12)}</div>
                                {/if}

                                {#if (msg.type === 'voice_note' || msg.type === 'file') && msg.attachment}
                                    <AttachmentRenderer {msg} />
                                {:else}
                                    <div class="text-[14px] leading-relaxed whitespace-pre-wrap break-all overflow-hidden">{msg.content}</div>
                                {/if}

                                {#if msg.linkPreview}
                                    <a href={msg.linkPreview.url} target="_blank" rel="noopener noreferrer" class="block mt-2 bg-black/5 rounded-xl overflow-hidden border border-black/5 hover:bg-black/10 transition no-underline">
                                        <div class="p-3">
                                            <div class="text-[10px] font-black text-blue-600 uppercase tracking-widest mb-1 flex items-center space-x-1">
                                                <span>{msg.linkPreview.siteName}</span>
                                                <LucideExternalLink size={10} />
                                            </div>
                                            <div class="text-[13px] font-bold text-gray-800 truncate mb-1">{msg.linkPreview.title}</div>
                                            <div class="text-[11px] text-gray-500 line-clamp-2 leading-snug">{msg.linkPreview.url}</div>
                                        </div>
                                    </a>
                                {/if}

                                <div class="flex items-center justify-end space-x-1 mt-1.5 opacity-60">
                                    {#if msg.isStarred}<LucideStar size={10} class="text-yellow-500 fill-yellow-500" />{/if}
                                    <span class="text-[9px] font-bold text-gray-400">{new Date(msg.timestamp).toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'})}</span>
                                    {#if msg.isMine}
                                        {#if msg.status === 'read'}<LucideCheckCheck size={12} class="text-blue-500" />
                                        {:else if msg.status === 'delivered'}<LucideCheckCheck size={12} class="text-gray-400" />
                                        {:else}<LucideCheck size={12} class="text-gray-400" />{/if}
                                    {/if}
                                </div>

                                <div class="absolute {msg.isMine ? '-left-12' : '-right-12'} top-0 bottom-0 opacity-0 group-hover:opacity-100 flex flex-col items-center justify-center space-y-1 transition-all duration-200">
                                    <button onclick={() => setReplyingTo(msg)} class="p-1.5 hover:bg-white rounded-full text-gray-400 hover:text-blue-500 shadow-sm transition active:scale-90" title="Reply"><LucideReply size={14} /></button>
                                    <button onclick={() => toggleStar(activeChat.peerHash, msg.id)} class="p-1.5 hover:bg-white rounded-full text-gray-400 hover:text-yellow-500 shadow-sm transition active:scale-90" title="Star"><LucideStar size={14} class={msg.isStarred ? 'fill-yellow-500 text-yellow-500' : ''} /></button>
                                </div>
                            </div>
                        </div>
                    </div>
            {/each}
            </div>
            
            {#if replyingTo}
                <div class="px-4 py-2 bg-white/95 backdrop-blur-md border-t border-gray-100 flex items-center animate-in slide-in-from-bottom duration-200">
                    <div class="flex-1 bg-gray-50 rounded-xl p-2 border-l-4 border-blue-500 flex items-center justify-between">
                        <div class="min-w-0">
                            <div class="text-[10px] font-black text-blue-600 truncate">{replyingTo.isMine ? 'You' : (replyingTo.senderAlias || 'Peer')}</div>
                            <div class="text-xs text-gray-500 truncate">{replyingTo.content}</div>
                        </div>
                        <button onclick={() => setReplyingTo(null)} class="p-1.5 hover:bg-gray-200 rounded-full text-gray-400"><LucideX size={16} /></button>
                    </div>
                </div>
            {/if}

            {#if $userStore.blockedHashes.includes(activeChat.peerHash)}
                <div class="p-6 bg-white/50 backdrop-blur-sm border-t border-gray-200 flex flex-col items-center justify-center space-y-3">
                    <div class="flex items-center space-x-2 text-gray-400 font-black text-[10px] uppercase tracking-widest">
                        <LucideBan size={14} />
                        <span>You blocked this contact</span>
                    </div>
                    <button 
                        onclick={() => toggleBlock(activeChat.peerHash)}
                        class="px-6 py-2 bg-blue-600 text-white text-xs font-bold rounded-xl shadow-lg hover:bg-blue-700 transition active:scale-[0.98]"
                    >
                        Unblock
                    </button>
                    <p class="text-[10px] text-gray-400 max-w-xs text-center leading-relaxed">Blocked contacts cannot call or message you, and you cannot send signals to them.</p>
                </div>
            {:else}
                <div class="p-3 bg-[#f0f2f5]/95 backdrop-blur-md flex items-center space-x-2 border-t border-gray-200 z-10 min-h-[64px]">
                    <input type="file" bind:this={fileInput} onchange={onFileSelect} class="hidden" />
                    
                    {#if isRecording}
                        <div class="flex-1 flex items-center justify-between bg-white px-4 py-2 rounded-2xl shadow-inner animate-in slide-in-from-bottom-2 duration-200 h-[48px]">
                            <div class="flex items-center space-x-3 flex-1 h-full">
                                <div class="w-2.5 h-2.5 bg-red-500 rounded-full animate-pulse shadow-[0_0_8px_rgba(239,68,68,0.5)]"></div>
                                <span class="text-[11px] font-black text-red-500 uppercase tracking-widest hidden sm:inline">Recording</span>
                                <span class="text-xs font-mono font-bold text-gray-700 min-w-[32px]">{formatRecordingTime(recordingSeconds)}</span>
                                <div class="flex-1 h-8 flex items-center px-4">
                                    <canvas bind:this={visualizerCanvas} width="160" height="32" class="w-full h-full opacity-60"></canvas>
                                </div>
                            </div>
                            <div class="flex items-center space-x-1 pl-2 border-l border-gray-100">
                                <button onclick={cancelRecording} class="p-2 text-gray-400 hover:text-red-500 transition-colors" title="Discard"><LucideTrash size={20} /></button>
                                <button onclick={stopRecording} class="p-2.5 bg-red-500 text-white rounded-xl shadow-lg hover:bg-red-600 transition-all active:scale-95" title="Stop & Listen"><LucideSquare size={16} fill="currentColor" /></button>
                            </div>
                        </div>
                    {:else if previewUrl}
                        <div class="flex-1 flex items-center space-x-3 bg-white px-4 py-2 rounded-2xl shadow-sm animate-in zoom-in-95">
                            <button onclick={cancelRecording} class="p-2 text-gray-400 hover:text-red-500 transition-colors"><LucideTrash size={20} /></button>
                            <div class="flex-1">
                                <VoiceNotePlayer src={previewUrl} id="preview" isMine={true} />
                            </div>
                            <button onclick={sendRecordedVoiceNote} class="p-3 bg-blue-600 text-white rounded-full hover:bg-blue-700 shadow-lg active:scale-95 transition-transform">
                                <LucideSend size={22} />
                            </button>
                        </div>
                    {:else}
                        <button onclick={() => fileInput?.click()} class="p-3 text-gray-400 hover:bg-gray-200 rounded-full transition"><LucidePaperclip size={24} /></button>
                        <textarea 
                            id="message-input"
                            bind:this={messageInputEl}
                            bind:value={messageInput}
                            onkeydown={handleKeydown}
                            rows="1"
                            class="flex-1 p-3 rounded-2xl border-none focus:ring-1 focus:ring-blue-500 bg-white resize-none max-h-[200px] overflow-y-auto custom-scrollbar"
                            placeholder="Type a message" 
                        ></textarea>
                        {#if !messageInput.trim()}
                            <button onclick={startRecording} class="p-3 text-gray-400 hover:bg-gray-100 rounded-full shadow-sm"><LucideMic size={24} /></button>
                        {:else}
                            <button onclick={handleSend} class="p-3 bg-blue-600 text-white rounded-full hover:bg-blue-700 shadow-lg active:scale-95 transition-transform"><LucideSend size={24} /></button>
                        {/if}
                    {/if}
                </div>
            {/if}
        </div>
        
        {#if showGallery}
            <div class="w-80 bg-white border-l border-gray-200 flex flex-col animate-in slide-in-from-right duration-300 z-[40]">
                <div class="p-4 border-b border-gray-100 flex justify-between items-center bg-gray-50">
                    <h2 class="font-bold text-gray-800 flex items-center space-x-2"><LucideInfo size={18} /><span>Info & Media</span></h2>
                    <button onclick={() => showGallery = false} class="text-gray-500 hover:text-red-500 transition"><LucideX size={20} /></button>
                </div>
                
                <div class="p-6 flex-1 overflow-y-auto custom-scrollbar space-y-8">
                    <div class="flex flex-col items-center space-y-4">
                        <div class="w-24 h-24 rounded-3xl bg-gradient-to-tr {activeChat.isGroup ? 'from-purple-500 to-indigo-600' : 'from-blue-400 to-blue-600'} flex items-center justify-center text-white text-3xl font-bold shadow-xl">
                            {#if activeChat.pfp}<img src={activeChat.pfp} alt="" class="w-full h-full object-cover rounded-3xl" />{:else}{(activeChat.localNickname || activeChat.peerAlias || '?')[0].toUpperCase()}{/if}
                        </div>
                        <div class="text-center">
                            <h3 class="text-xl font-bold text-gray-900">{activeChat.localNickname || activeChat.peerAlias || 'Unknown'}</h3>
                            {#if activeChat.localNickname && activeChat.peerAlias}
                                <p class="text-[10px] font-bold text-blue-600 uppercase mb-1">Peer Alias: {activeChat.peerAlias}</p>
                            {/if}
                            <p class="text-[10px] font-mono text-gray-400 break-all">{activeChat.peerHash}</p>
                        </div>
                    </div>
                    
                    {#if activeChat.isGroup}
                        <div class="space-y-2">
                            <h4 class="text-xs font-bold text-gray-400 uppercase tracking-widest">Group Invite Link</h4>
                            <div class="bg-gray-50 p-3 rounded-xl border border-gray-100 flex items-center justify-between">
                                <span class="text-[11px] font-mono text-blue-600 truncate">entropy://{activeChat.peerHash.slice(0, 32)}...</span>
                                <button onclick={copyInvite} class="p-2 hover:bg-blue-50 rounded-lg text-blue-600 transition">
                                    {#if inviteCopied}<LucideCheckIcon size={16} />{:else}<LucideCopy size={16} />{/if}
                                </button>
                            </div>
                        </div>
                    {/if}

                    <div class="space-y-4">
                        <div class="flex justify-between items-center">
                            <h4 class="text-xs font-bold text-gray-400 uppercase tracking-widest">Shared Media ({mediaMessages.length})</h4>
                            <LucideImage size={14} class="text-gray-300" />
                        </div>
                        {#if mediaMessages.length === 0}
                            <div class="bg-gray-50 border-2 border-dashed border-gray-200 rounded-2xl h-32 flex items-center justify-center text-xs text-gray-400">No media shared yet</div>
                        {:else}
                            <div class="grid grid-cols-3 gap-2">
                                {#each mediaMessages.slice(0, 9) as m}
                                    <div class="aspect-square bg-blue-50 rounded-lg flex items-center justify-center text-blue-300 relative group/file">
                                        <LucideFile size={20} />
                                        <div class="absolute inset-0 bg-blue-600/80 opacity-0 group-hover/file:opacity-100 flex items-center justify-center text-white text-[10px] p-1 text-center truncate rounded-lg transition-opacity duration-200">View</div>
                                    </div>
                                {/each}
                            </div>
                        {/if}
                    </div>

                    <div class="space-y-4">
                        <div class="flex justify-between items-center">
                            <h4 class="text-xs font-bold text-gray-400 uppercase tracking-widest">Shared Links ({linkMessages.length})</h4>
                            <LucideLink size={14} class="text-gray-300" />
                        </div>
                        <div class="space-y-2">
                             {#each linkMessages.slice(0, 5) as m}
                                <a href={m.linkPreview!.url} target="_blank" class="block p-3 bg-gray-50 border border-transparent hover:border-blue-100 hover:bg-blue-50/50 rounded-xl transition duration-200 no-underline">
                                    <div class="text-[11px] font-bold text-gray-800 truncate">{m.linkPreview!.title}</div>
                                    <div class="text-[9px] text-blue-500 truncate mt-1">{m.linkPreview!.url}</div>
                                </a>
                             {/each}
                        </div>
                    </div>
                </div>
            </div>
        {/if}
    </div>
{/if}

<style>
    .custom-scrollbar::-webkit-scrollbar { width: 5px; }
    .custom-scrollbar::-webkit-scrollbar-thumb { background: rgba(0,0,0,0.1); border-radius: 10px; }
    @keyframes bounce-subtle {
        0%, 100% { transform: translateY(0); }
        50% { transform: translateY(-10px); }
    }
    .animate-bounce-subtle {
        animation: bounce-subtle 3s ease-in-out infinite;
    }
</style>
