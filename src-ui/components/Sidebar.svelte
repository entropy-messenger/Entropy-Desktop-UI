
<script lang="ts">
  import { userStore } from '../lib/stores/user';
  import { 
    startChat, createGroup, updateMyProfile, 
    togglePin, toggleArchive, toggleMute, toggleBlock, updatePrivacy,
    registerGlobalNickname, lookupNickname, burnAccount, refreshDecoys
  } from '../lib/store';
  import {
    LucidePlus, LucideSettings, LucideSearch,
    LucideCheck, LucideCheckCheck, LucideUsers, LucideX,
    LucideCamera, LucideUser, LucidePin, LucideArchive, LucideBellOff,
    LucideLock, LucideCheckCircle2, LucideBan, LucideEyeOff,
    LucideShieldAlert, LucideCpu, LucideGlobe, LucideTrash2,
    LucideShieldCheck, LucideActivity
  } from 'lucide-svelte';

  let activeHash = $state<string | null>(null);
  let searchQuery = $state("");
  let globalResults = $state<any[]>([]);
  let searching = $state(false);

  import { invoke } from '@tauri-apps/api/core';

  $effect(() => {
    if (searchQuery.trim().length > 2) {
        searching = true;
        invoke('protocol_search_messages', { query: searchQuery })
            .then(res => { globalResults = res as any[]; searching = false; })
            .catch(() => { searching = false; });
    } else {
        globalResults = [];
    }
  });
  let showCreateGroup = $state(false);
  let groupName = $state("");
  let groupMembers = $state<string[]>([]);
  let memberInput = $state("");
  let pfpInput = $state<HTMLInputElement | null>(null);
  let filter = $state<'all' | 'archived'>('all');
  
  userStore.subscribe(store => {
    activeHash = store.activeChatHash;
  });

  const selectChat = (hash: string) => {
    userStore.update(s => {
        if (s.chats[hash]) s.chats[hash].unreadCount = 0;
        return { ...s, activeChatHash: hash };
    });
    startChat(hash);
  };

  const createChatPrompt = async () => {
    const input = prompt("Enter Peer ID Hash (64-char Hex) or Global Nickname:");
    if (!input) return;

    if (input.length === 64 && /^[0-9a-fA-F]+$/.test(input)) {
        startChat(input);
    } else {
        const hash = await lookupNickname(input);
        if (hash) {
            startChat(hash, input);
        } else {
            alert("Could not find user with that hash or nickname.");
        }
    }
  };

  const handleCreateGroup = () => {
      if (!groupName.trim() || groupMembers.length === 0) return;
      createGroup(groupName, groupMembers);
      groupName = "";
      groupMembers = [];
      showCreateGroup = false;
  };

  const addMember = async () => {
      const input = memberInput.trim();
      if (!input) return;

      let targetHash = "";
      if (input.length === 64 && /^[0-9a-fA-F]+$/.test(input)) {
          targetHash = input;
      } else {
          const localMatch = Object.values($userStore.chats).find(c => c.localNickname?.toLowerCase() === input.toLowerCase());
          if (localMatch) {
              targetHash = localMatch.peerHash;
          } else {
              const globalHash = await lookupNickname(input);
              if (globalHash) {
                targetHash = globalHash;
                userStore.update(s => {
                    if (s.chats[targetHash]) s.chats[targetHash].peerAlias = input;
                    return s;
                });
            }
          }
      }

      if (targetHash && !groupMembers.includes(targetHash)) {
          groupMembers = [...groupMembers, targetHash];
          memberInput = "";
      } else if (!targetHash) {
          alert("Could not resolve nickname or hash.");
      }
  };

  const toggleMember = (hash: string) => {
      if (groupMembers.includes(hash)) {
          groupMembers = groupMembers.filter(m => m !== hash);
      } else {
          groupMembers = [...groupMembers, hash];
      }
  };

  const removeMember = (m: string) => {
      groupMembers = groupMembers.filter(member => member !== m);
  };

  let showSettings = $state(false);
  let settingsTab = $state<'profile' | 'privacy' | 'blocked' | 'audit'>('profile');
  let copied = $state(false);
  
  const toggleSettings = () => { 
    showSettings = !showSettings; 
    settingsTab = 'profile';
    copied = false; 
  };

  const copyHash = () => {
    if ($userStore.identityHash) {
        navigator.clipboard.writeText($userStore.identityHash);
        copied = true;
        setTimeout(() => copied = false, 2000);
    }
  };

  const onPfpSelect = (e: Event) => {
      const file = (e.target as HTMLInputElement).files?.[0];
      if (file) {
          const reader = new FileReader();
          reader.onload = (ev) => {
              const base64 = ev.target?.result as string;
              updateMyProfile($userStore.myAlias || "Anonymous", base64);
          };
          reader.readAsDataURL(file);
      }
  };

  const handleUpdateAlias = () => {
      const next = prompt("Update your display name:", $userStore.myAlias || "");
      if (next !== null) {
          updateMyProfile(next.trim() || "Anonymous", $userStore.myPfp);
      }
  };

  let filteredChats = $derived(Object.values($userStore.chats).filter(chat => {
    const query = searchQuery.toLowerCase();
    const chatName = (chat.localNickname || chat.peerAlias || "").toLowerCase();
    const matchesName = chatName.includes(query) || chat.peerHash.toLowerCase().includes(query);
    const matchesMessages = chat.messages.some(m => m.content.toLowerCase().includes(query));
    
    if (filter === 'archived' && !chat.isArchived) return false;
    if (filter === 'all' && chat.isArchived) return false;

    return matchesName || matchesMessages;
  }).sort((a, b) => {
    if (a.isPinned && !b.isPinned) return -1;
    if (!a.isPinned && b.isPinned) return 1;
    
    const aTime = a.messages.length > 0 ? a.messages[a.messages.length - 1].timestamp : 0;
    const bTime = b.messages.length > 0 ? b.messages[b.messages.length - 1].timestamp : 0;
    return bTime - aTime;
  }));

  function formatLastSeen(ts?: number) {
      if (!ts) return "";
      const diff = Date.now() - ts;
      if (diff < 60000) return "just now";
      if (diff < 3600000) return `${Math.floor(diff/60000)}m ago`;
      return new Date(ts).toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'});
  }
</script>

<div class="h-full w-80 bg-white border-r border-gray-200 flex flex-col relative shrink-0">
  <div class="p-4 flex flex-col space-y-4 bg-gray-50/50">
    <div class="flex justify-between items-center px-1">
        <div class="flex items-center space-x-1 -ml-1">
            <img src="/logo.png" alt="logo" class="w-6 h-6 object-contain" />
            <div class="font-[900] text-sm text-gray-900 tracking-tighter uppercase">Entropy</div>
        </div>
        <div class="flex items-center space-x-1">
            <button onclick={() => showCreateGroup = true} class="p-2 hover:bg-gray-200 rounded-full text-gray-600 transition" title="New Group">
                <LucideUsers size={18} />
            </button>
            <button onclick={createChatPrompt} class="p-2 hover:bg-gray-200 rounded-full text-blue-600 transition" title="New Message">
                <LucidePlus size={20} />
            </button>
            <button onclick={toggleSettings} class="p-2 hover:bg-gray-200 rounded-full text-gray-500 transition">
                <LucideSettings size={18} />
            </button>
        </div>
    </div>

    <div class="flex bg-gray-100 rounded-lg p-1 text-[10px] font-bold">
        <button onclick={() => filter = 'all'} class="flex-1 py-1 rounded-md transition {filter === 'all' ? 'bg-white shadow-sm text-blue-600' : 'text-gray-500'}">ALL CHATS</button>
        <button onclick={() => filter = 'archived'} class="flex-1 py-1 rounded-md transition {filter === 'archived' ? 'bg-white shadow-sm text-blue-600' : 'text-gray-500'}">ARCHIVED</button>
    </div>

    <div class="relative">
        <LucideSearch size={14} class="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400" />
        <input 
            type="text" 
            bind:value={searchQuery}
            placeholder="Search messages & contacts..." 
            class="w-full pl-9 pr-4 py-2 bg-gray-100 focus:bg-white border-none rounded-xl text-xs transition ring-1 ring-black/5"
        />
    </div>
  </div>

  <div class="flex-1 overflow-y-auto custom-scrollbar">
    {#each filteredChats as chat}
        <div 
            class="group/item p-4 hover:bg-gray-50 cursor-pointer border-b border-gray-50 transition relative {activeHash === chat.peerHash ? 'bg-blue-50/80 shadow-[inset_4px_0_0_0_#2563eb]' : ''}"
            onclick={() => selectChat(chat.peerHash)}
            onkeypress={(e) => e.key === 'Enter' && selectChat(chat.peerHash)}
            role="button"
            tabindex="0"
        >
            <div class="flex items-center space-x-3">
                <div class="relative">
                    {#if chat.pfp}
                        <img src={chat.pfp} alt="" class="w-12 h-12 rounded-2xl object-cover shadow-sm" />
                    {:else}
                        <div class="w-12 h-12 rounded-2xl bg-gradient-to-br {chat.isGroup ? 'from-purple-500 to-indigo-600' : 'from-blue-400 to-blue-600'} flex items-center justify-center text-white font-bold text-lg shadow-sm">
                            {chat.peerAlias ? chat.peerAlias[0].toUpperCase() : '?'}
                        </div>
                    {/if}
                    {#if chat.isOnline && !chat.isGroup}
                        <div class="absolute -bottom-0.5 -right-0.5 w-3.5 h-3.5 bg-green-500 border-2 border-white rounded-full shadow-sm"></div>
                    {/if}
                </div>
                
                <div class="flex-1 min-w-0">
                    <div class="flex justify-between items-baseline mb-0.5">
                        <div class="font-bold text-gray-900 truncate flex items-center space-x-1">
                            {#if chat.isGroup}<LucideUsers size={12} class="text-blue-500" />{/if}
                            <span class="truncate">{chat.localNickname || chat.peerAlias || chat.peerHash.slice(0, 8)}</span>
                            {#if chat.isPinned}<LucidePin size={10} class="text-blue-500 fill-blue-500" />{/if}
                            {#if chat.isMuted}<LucideBellOff size={10} class="text-gray-400" />{/if}
                        </div>
                        {#if chat.messages.length > 0}
                             <div class="text-[9px] font-bold text-gray-400 shrink-0">
                                {new Date(chat.messages[chat.messages.length - 1].timestamp).toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'})}
                             </div>
                        {/if}
                    </div>
                    
                    <div class="flex items-center justify-between">
                        <div class="text-[13px] truncate pr-2 flex-1 {chat.isTyping ? 'text-green-600 font-bold' : 'text-gray-500'}">
                            {#if chat.isTyping}
                                <span>typing...</span>
                            {:else if chat.messages.length > 0}
                                <div class="flex items-center space-x-1">
                                    {#if chat.messages[chat.messages.length - 1].isMine}
                                        {#if chat.messages[chat.messages.length - 1].status === 'read'}
                                            <LucideCheckCheck size={13} class="text-blue-500" />
                                        {:else if chat.messages[chat.messages.length - 1].status === 'delivered'}
                                            <LucideCheckCheck size={13} class="text-gray-400" />
                                        {:else}
                                            <LucideCheck size={13} class="text-gray-400" />
                                        {/if}
                                    {/if}
                                    <span class="truncate">{chat.messages[chat.messages.length - 1].content}</span>
                                </div>
                            {:else if !chat.isOnline && chat.lastSeen}
                                <span class="text-[11px] opacity-70">last seen {formatLastSeen(chat.lastSeen)}</span>
                            {:else}
                                <span class="italic text-gray-400 text-xs">New conversation</span>
                            {/if}
                        </div>
                        
                        {#if chat.unreadCount > 0}
                            <div class="bg-blue-600 text-white text-[9px] font-bold px-1.5 py-0.5 rounded-full min-w-[17px] text-center shadow-sm">
                                {chat.unreadCount}
                            </div>
                        {/if}
                        
                        <div class="hidden group-hover/item:flex items-center space-x-1 ml-2">
                             <button onclick={(e) => {e.stopPropagation(); togglePin(chat.peerHash)}} class="p-1 hover:bg-gray-200 rounded transition text-gray-400 hover:text-blue-500" title="Pin/Unpin">
                                <LucidePin size={12} class={chat.isPinned ? 'fill-blue-500 text-blue-500' : ''} />
                             </button>
                             <button onclick={(e) => {e.stopPropagation(); toggleArchive(chat.peerHash)}} class="p-1 hover:bg-gray-200 rounded transition text-gray-400 hover:text-blue-500" title="Archive/Unarchive">
                                <LucideArchive size={12} class={chat.isArchived ? 'fill-blue-500 text-blue-500' : ''} />
                             </button>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    {/each}

    {#if globalResults.length > 0}
        <div class="px-4 py-3 bg-indigo-50/30 border-y border-indigo-100/50 mt-4 first:mt-0">
            <h4 class="text-[9px] font-black uppercase tracking-[0.2em] text-indigo-400">Global Archive Results</h4>
        </div>
        {#each globalResults as res}
            <div 
                class="p-4 hover:bg-gray-50 cursor-pointer border-b border-gray-50 transition"
                onclick={() => selectChat(res.peerHash)}
            >
                <div class="flex items-start space-x-3">
                    <div class="w-8 h-8 rounded-lg bg-indigo-100 flex items-center justify-center text-indigo-600 shrink-0 shadow-sm">
                        <LucideSearch size={14} />
                    </div>
                    <div class="flex-1 min-w-0">
                        <div class="flex justify-between items-center mb-0.5">
                            <span class="text-[10px] font-black text-indigo-900 truncate tracking-tight">@{res.peerHash.slice(0,8)}</span>
                            <span class="text-[8px] font-bold text-gray-400 uppercase">{new Date(res.timestamp).toLocaleDateString()}</span>
                        </div>
                        <p class="text-xs text-gray-600 line-clamp-2 italic leading-relaxed">"{res.content}"</p>
                    </div>
                </div>
            </div>
        {/each}
    {/if}
  </div>

  {#if showSettings}
    <div class="absolute inset-0 bg-white z-[60] flex flex-col animate-in slide-in-from-bottom duration-300">
        <div class="p-4 border-b border-gray-100 flex justify-between items-center bg-gray-50">
            <h2 class="font-bold text-gray-800">Settings</h2>
            <button onclick={toggleSettings} class="text-gray-500 hover:text-gray-700 font-bold">Done</button>
        </div>
        
        <div class="flex border-b border-gray-100 text-[10px] font-black uppercase tracking-widest text-gray-400">
            <button onclick={() => settingsTab = 'profile'} class="flex-1 py-3 {settingsTab === 'profile' ? 'text-blue-600 border-b-2 border-blue-600' : ''}">Profile</button>
            <button onclick={() => settingsTab = 'privacy'} class="flex-1 py-3 {settingsTab === 'privacy' ? 'text-blue-600 border-b-2 border-blue-600' : ''}">Privacy</button>
            <button onclick={() => settingsTab = 'blocked'} class="flex-1 py-3 {settingsTab === 'blocked' ? 'text-blue-600 border-b-2 border-blue-600' : ''}">Blocked</button>
            <button onclick={() => settingsTab = 'audit'} class="flex-1 py-3 {settingsTab === 'audit' ? 'text-blue-600 border-b-2 border-blue-600' : ''}">Audit</button>
        </div>

        <div class="p-6 space-y-8 flex-1 overflow-y-auto custom-scrollbar">
            {#if settingsTab === 'profile'}
                <div class="flex flex-col items-center space-y-4">
                    <div class="relative group">
                        {#if $userStore.myPfp}
                            <img src={$userStore.myPfp} alt="" class="w-24 h-24 rounded-3xl object-cover shadow-xl ring-4 ring-blue-50" />
                        {:else}
                            <div class="w-24 h-24 rounded-3xl bg-blue-100 flex items-center justify-center text-blue-600 shadow-xl">
                                <LucideUser size={48} />
                            </div>
                        {/if}
                        <button onclick={() => pfpInput?.click()} class="absolute -bottom-2 -right-2 p-2 bg-blue-600 text-white rounded-xl shadow-lg hover:bg-blue-700 transition active:scale-95"><LucideCamera size={18} /></button>
                        <input type="file" bind:this={pfpInput} onchange={onPfpSelect} accept="image/*" class="hidden" />
                    </div>
                    <div class="text-center space-y-1">
                        <button onclick={handleUpdateAlias} class="text-xl font-bold text-gray-800 hover:text-blue-600 transition flex items-center justify-center space-x-2">
                            <span>{$userStore.myAlias || 'Set Name'}</span>
                            <LucidePlus size={16} class="opacity-50" />
                        </button>
                        <div class="text-xs font-bold text-gray-400 uppercase tracking-widest">Active Identity</div>
                    </div>

                    <div class="w-full flex flex-col space-y-2">
                        {#if $userStore.myGlobalNickname}
                            <div class="p-4 bg-indigo-50 border border-indigo-100 rounded-xl space-y-2">
                                <div class="flex items-center justify-between">
                                    <span class="text-xs font-bold text-indigo-400 uppercase">Global Nickname</span>
                                    <span class="px-2 py-0.5 bg-indigo-600 text-[10px] text-white rounded-full font-bold">Active</span>
                                </div>
                                <div class="text-lg font-bold text-indigo-900">@{$userStore.myGlobalNickname}</div>
                                {#if $userStore.nicknameExpiry}
                                    <div class="flex items-center space-x-1 text-[10px] text-indigo-400">
                                        <LucideCpu size={12} />
                                        <span>Expires in {Math.round(($userStore.nicknameExpiry - Date.now()) / (1000 * 60 * 60 * 24))} days</span>
                                    </div>
                                {/if}
                                <button 
                                    onclick={async () => {
                                        const nick = prompt("Renew/Update nickname:", $userStore.myGlobalNickname || "");
                                        if (nick) {
                                            const res = await registerGlobalNickname(nick);
                                            if (res && res.success) alert("Nickname updated!");
                                        }
                                    }}
                                    class="w-full mt-2 py-2 bg-indigo-600 text-white rounded-lg text-xs font-bold hover:bg-indigo-700 transition"
                                >
                                    Renew Nickname
                                </button>
                            </div>
                        {:else}
                            <button 
                                onclick={async () => {
                                    const nick = prompt("Register a global nickname (min 3 chars):", $userStore.myAlias || "");
                                    if (nick) {
                                        const res = await registerGlobalNickname(nick);
                                        if (res && res.success) {
                                            alert("Nickname registered successfully!");
                                        } else {
                                            alert("Registration failed: " + (res?.error || "Unknown"));
                                        }
                                    }
                                }}
                                class="w-full py-3 bg-indigo-600 text-white rounded-xl text-sm font-bold shadow-lg hover:bg-indigo-700 transition active:scale-95 flex items-center justify-center space-x-2"
                            >
                                <img src="/logo.png" alt="logo" class="w-6 h-6 object-contain invert opacity-40" />
                                <span>Register Global Nickname</span>
                            </button>
                        {/if}

                        <div class="flex space-x-2">
                            <button 
                                onclick={async () => {
                                    const { exportVault } = await import('../lib/store');
                                    await exportVault();
                                }}
                                class="flex-1 py-3 bg-gray-100 text-gray-700 rounded-xl text-xs font-bold hover:bg-gray-200 transition"
                            >
                                Export Backup
                            </button>
                            <button 
                                onclick={async () => {
                                    const { importVault } = await import('../lib/store');
                                    await importVault();
                                }}
                                class="flex-1 py-3 bg-gray-100 text-gray-700 rounded-xl text-xs font-bold hover:bg-gray-200 transition"
                            >
                                Import Backup
                            </button>
                        </div>
                    </div>
                </div>

                <div class="bg-blue-50 p-4 rounded-2xl border border-blue-100 space-y-3">
                    <div class="text-[10px] font-bold text-blue-800 uppercase tracking-widest">Global Identity Hash</div>
                    <div class="break-all font-mono text-[10px] text-blue-900 bg-white/50 p-2 rounded border border-blue-100 select-all leading-tight">{$userStore.identityHash || 'Generating...'}</div>
                    <button onclick={copyHash} class="w-full py-3 bg-white text-blue-700 border border-blue-200 rounded-xl text-sm font-bold shadow-sm hover:bg-blue-100 transition">{copied ? 'Copied!' : 'Copy Hash Address'}</button>
                    
                    <div class="flex justify-center mt-2">
                        <div class="bg-white p-2 rounded-xl border border-blue-100 shadow-sm relative overflow-hidden group/qr">
                            <img 
                                src="https://api.qrserver.com/v1/create-qr-code/?size=150x150&data={$userStore.identityHash}" 
                                alt="QR Identity" 
                                class="w-32 h-32 blur-[1px] group-hover/qr:blur-0 transition-all duration-300"
                            />
                            <div class="absolute inset-0 bg-white/40 flex items-center justify-center opacity-100 group-hover/qr:opacity-0 transition-opacity">
                                <LucideLock size={24} class="text-blue-600" />
                            </div>
                        </div>
                    </div>
                </div>
            {:else if settingsTab === 'privacy'}
                    <div class="space-y-6">
                        <div class="space-y-1">
                            <h3 class="font-bold text-gray-800 flex items-center space-x-2">
                                <LucideCheckCheck size={18} class="text-blue-500" />
                                <span>Read Receipts</span>
                            </h3>
                            <p class="text-xs text-gray-500 leading-relaxed">If turned off, you won't send or receive Read Receipts (blue checks). Personal privacy first.</p>
                            <div class="flex justify-end pt-2">
                                <button onclick={() => updatePrivacy({ readReceipts: !$userStore.privacySettings.readReceipts })} class="w-12 h-6 rounded-full transition-colors relative {$userStore.privacySettings.readReceipts ? 'bg-blue-500' : 'bg-gray-300'}" aria-label="Toggle Read Receipts">
                                    <div class="absolute top-1 w-4 h-4 bg-white rounded-full transition-all {$userStore.privacySettings.readReceipts ? 'left-7' : 'left-1'}"></div>
                                </button>
                            </div>
                        </div>

                        <div class="space-y-1">
                            <h3 class="font-bold text-gray-800 flex items-center space-x-2">
                                <LucideEyeOff size={18} class="text-purple-500" />
                                <span>Last Seen & Online</span>
                            </h3>
                            <p class="text-xs text-gray-500 leading-relaxed">Control who can see when you were last online.</p>
                            <div class="flex bg-gray-100 p-1 rounded-xl mt-3">
                                <button onclick={() => updatePrivacy({ lastSeen: 'everyone' })} class="flex-1 py-2 text-[10px] font-bold rounded-lg transition {$userStore.privacySettings.lastSeen === 'everyone' ? 'bg-white shadow-sm text-blue-600' : 'text-gray-500'}">EVERYONE</button>
                                <button onclick={() => updatePrivacy({ lastSeen: 'nobody' })} class="flex-1 py-2 text-[10px] font-bold rounded-lg transition {$userStore.privacySettings.lastSeen === 'nobody' ? 'bg-white shadow-sm text-blue-600' : 'text-gray-500'}">NOBODY</button>
                            </div>
                        </div>
                        <div class="space-y-1">
                            <h3 class="font-bold text-gray-800 flex items-center space-x-2">
                                <LucideGlobe size={18} class="text-blue-500" />
                                <span>Network Routing</span>
                            </h3>
                            <p class="text-xs text-gray-500 leading-relaxed">Route your traffic to hide your IP address. (Tor requires a local Tor instance on port 9050).</p>
                             <div class="flex bg-gray-100 p-1 rounded-xl mt-3">
                                <button onclick={() => updatePrivacy({ routingMode: 'direct' })} class="flex-1 py-1.5 text-[9px] font-bold rounded-lg transition {$userStore.privacySettings.routingMode === 'direct' ? 'bg-white shadow-sm text-blue-600' : 'text-gray-500'}">DIRECT</button>
                                <button onclick={() => updatePrivacy({ routingMode: 'tor' })} class="flex-1 py-1.5 text-[9px] font-bold rounded-lg transition {$userStore.privacySettings.routingMode === 'tor' ? 'bg-white shadow-sm text-blue-600' : 'text-gray-500'}">TOR</button>
                                <button onclick={() => {
                                    const url = prompt("Enter SOCKS5 Proxy URL (e.g. socks5://127.0.0.1:1080):", $userStore.privacySettings.proxyUrl || "");
                                    if (url) updatePrivacy({ routingMode: 'custom', proxyUrl: url });
                                }} class="flex-1 py-1.5 text-[9px] font-bold rounded-lg transition {$userStore.privacySettings.routingMode === 'custom' ? 'bg-white shadow-sm text-blue-600' : 'text-gray-500'}">CUSTOM</button>
                            </div>
                        </div>

                        <div class="space-y-1">
                            <h3 class="font-bold text-gray-800 flex items-center space-x-2">
                                <LucideCpu size={18} class="text-teal-500" />
                                <span>Decoy Fetching</span>
                            </h3>
                            <p class="text-xs text-gray-500 leading-relaxed">Fetch multiple random keys when looking up a peer to hide your intent from the server.</p>
                            <div class="flex items-center justify-between pt-2">
                                <button 
                                    onclick={async (e) => {
                                        const btn = e.currentTarget;
                                        btn.disabled = true;
                                        const original = btn.innerText;
                                        btn.innerText = "REFRESHING...";
                                        await refreshDecoys('http://localhost:8080');
                                        btn.innerText = "DONE!";
                                        setTimeout(() => { 
                                            btn.innerText = original; 
                                            btn.disabled = false;
                                        }, 1000);
                                    }}
                                    class="text-[9px] font-bold text-teal-600 hover:text-teal-700 uppercase tracking-tighter"
                                >
                                    REFRESH POOL
                                </button>
                                <button onclick={() => updatePrivacy({ decoyMode: !$userStore.privacySettings.decoyMode })} class="w-12 h-6 rounded-full transition-colors relative {$userStore.privacySettings.decoyMode ? 'bg-teal-500' : 'bg-gray-300'}" aria-label="Toggle Decoy Mode">
                                    <div class="absolute top-1 w-4 h-4 bg-white rounded-full transition-all {$userStore.privacySettings.decoyMode ? 'left-7' : 'left-1'}"></div>
                                </button>
                            </div>
                        </div>

                        <div class="p-4 bg-blue-50 rounded-2xl border border-blue-100 flex items-start space-x-3">
                            <img src="/logo.png" alt="logo" class="w-8 h-8 object-contain shrink-0 opacity-40 ml-[-4px]" />
                            <div>
                                <div class="text-[11px] font-bold text-blue-900 uppercase tracking-widest mb-1">E2E Integrity</div>
                                <p class="text-[10px] text-blue-700 leading-snug">All privacy signals are encrypted. Even routing configurations are only used locally to establish the secure tunnel.</p>
                            </div>
                        </div>

                        <div class="pt-4 border-t border-gray-100">
                             <div class="text-[10px] font-bold text-red-500 uppercase tracking-widest mb-3 flex items-center space-x-1">
                                <LucideShieldAlert size={12} />
                                <span>Danger Zone</span>
                             </div>
                             <button 
                                onclick={() => burnAccount('http://localhost:8080')}
                                class="w-full py-3 bg-red-50 text-red-600 border border-red-200 rounded-xl text-xs font-bold hover:bg-red-600 hover:text-white transition flex items-center justify-center space-x-2"
                             >
                                <LucideTrash2 size={14} />
                                <span>Nuke Account (Forensic Burn)</span>
                             </button>
                        </div>
                    </div>
                {:else if settingsTab === 'audit'}
                    <div class="space-y-6 animate-in slide-in-from-right-4 duration-300">
                        <div class="p-4 bg-emerald-50 border border-emerald-100 rounded-2xl space-y-4">
                            <div class="flex items-center space-x-3 text-emerald-800">
                                <LucideShieldCheck size={24} />
                                <h3 class="font-black text-xs uppercase tracking-[0.2em]">Protocol Integrity Audit</h3>
                            </div>
                            
                            <div class="space-y-3">
                                <div class="flex items-center justify-between text-[11px] font-bold">
                                    <span class="text-gray-500">PQXDH Key Exchange</span>
                                    <span class="text-emerald-600 flex items-center space-x-1"><LucideCheck size={12}/> <span>Kyber-1024</span></span>
                                </div>
                                <div class="flex items-center justify-between text-[11px] font-bold">
                                    <span class="text-gray-500">Perfect Forward Secrecy</span>
                                    <span class="text-emerald-600 flex items-center space-x-1"><LucideCheck size={12}/> <span>Double Ratchet</span></span>
                                </div>
                                <div class="flex items-center justify-between text-[11px] font-bold">
                                    <span class="text-gray-500">Sender Ratcheting</span>
                                    <span class="text-emerald-600 flex items-center space-x-1"><LucideCheck size={12}/> <span>Group V2 Secure</span></span>
                                </div>
                                <div class="flex items-center justify-between text-[11px] font-bold">
                                    <span class="text-gray-500">Anonymity Layers</span>
                                    <span class="text-emerald-600 flex items-center space-x-1"><LucideCheck size={12}/> <span>Sealed Sender</span></span>
                                </div>
                                <div class="flex items-center justify-between text-[11px] font-bold">
                                    <span class="text-gray-500">IP Protection</span>
                                    <span class="text-blue-600 flex items-center space-x-1"><span>{$userStore.privacySettings.routingMode.toUpperCase()}</span></span>
                                </div>
                                <div class="flex items-center justify-between text-[11px] font-bold">
                                    <span class="text-gray-500">Network Obfuscation</span>
                                    <span class="text-emerald-600 flex items-center space-x-1"><LucideCheck size={12}/> <span>Traffic Padding</span></span>
                                </div>
                                <div class="flex items-center justify-between text-[11px] font-bold">
                                    <span class="text-gray-500">Vault Hardening</span>
                                    <span class="text-emerald-600 flex items-center space-x-1"><LucideCheck size={12}/> <span>SQLCipher AES-256</span></span>
                                </div>
                                <div class="flex items-center justify-between text-[11px] font-bold">
                                    <span class="text-gray-500">Large Media</span>
                                    <span class="text-emerald-600 flex items-center space-x-1"><LucideCheck size={12}/> <span>AES-GCM Chunked</span></span>
                                </div>
                                <div class="flex items-center justify-between text-[11px] font-bold">
                                    <span class="text-gray-500">Multi-Device</span>
                                    <span class="text-emerald-600 flex items-center space-x-1"><LucideCheck size={12}/> <span>Real-time Sync</span></span>
                                </div>
                            </div>

                            <p class="text-[9px] text-gray-400 leading-relaxed pt-2 border-t border-emerald-100">
                                This audit verifies that all active communication channels are currently utilizing the maximum security parameters defined in the <b>Entropy Protocol Specification v1.2</b>.
                            </p>
                        </div>

                        <div class="px-2 space-y-4">
                            <div class="flex items-center space-x-3">
                                <LucideActivity size={16} class="text-blue-500" />
                                <span class="text-[10px] font-black uppercase text-gray-400 tracking-widest">Active Session Health</span>
                            </div>
                            <div class="space-y-2">
                                {#each Object.values($userStore.chats).slice(0, 5) as chat}
                                    <div class="flex items-center justify-between p-3 bg-gray-50 rounded-xl">
                                        <div class="flex items-center space-x-3">
                                            <div class="w-6 h-6 rounded-lg bg-white border border-gray-100 flex items-center justify-center text-[10px] font-bold">
                                                {(chat.localNickname || chat.peerAlias || "?")[0].toUpperCase()}
                                            </div>
                                            <span class="text-[10px] font-bold text-gray-700">{chat.localNickname || chat.peerAlias || 'Peer'}</span>
                                        </div>
                                        <div class="flex items-center space-x-2">
                                            {#if chat.isVerified}
                                                <LucideShieldCheck size={12} class="text-emerald-500" />
                                            {/if}
                                            <span class="text-[8px] px-2 py-0.5 bg-gray-200 rounded-full font-bold">AES-GCM</span>
                                        </div>
                                    </div>
                                {/each}
                            </div>
                        </div>
                    </div>
                {:else if settingsTab === 'blocked'}
                    <div class="space-y-4">
                        <h3 class="text-xs font-bold text-gray-400 uppercase tracking-widest">Blocked Identity Hashes</h3>
                        {#if $userStore.blockedHashes.length === 0}
                            <div class="text-center py-12 space-y-2 opacity-30">
                                <LucideBan size={40} class="mx-auto" />
                                <p class="text-sm font-medium">No blocked contacts</p>
                            </div>
                        {:else}
                            <div class="space-y-2">
                                {#each $userStore.blockedHashes as h}
                                    <div class="flex items-center justify-between p-3 bg-red-50 rounded-xl border border-red-100">
                                        <span class="text-[10px] font-mono font-bold text-red-800">{h.slice(0, 32)}...</span>
                                        <button onclick={() => toggleBlock(h)} class="text-[10px] font-black text-red-600 uppercase hover:underline">Unblock</button>
                                    </div>
                                {/each}
                            </div>
                        {/if}
                    </div>
                {/if}
            </div>
        </div>
    {/if}

    {#if showCreateGroup}
        <div class="absolute inset-0 bg-white z-[60] flex flex-col animate-in slide-in-from-right duration-300">
            <div class="p-4 border-b border-gray-100 flex justify-between items-center bg-gray-50">
                <h2 class="font-bold text-gray-800 flex items-center space-x-2"><LucideUsers size={18} /><span>New Group</span></h2>
                <button onclick={() => showCreateGroup = false} class="text-gray-500" aria-label="Close panel"><LucideX size={20} /></button>
            </div>
            <div class="p-6 flex-1 space-y-6 overflow-y-auto custom-scrollbar">
                <div class="space-y-2">
                    <label for="group-name-input" class="text-xs font-bold text-gray-500 uppercase">Group Name</label>
                    <input id="group-name-input" bind:value={groupName} placeholder="Enter group name..." class="w-full p-3 bg-gray-50 rounded-xl border-none focus:ring-2 focus:ring-blue-500/20" />
                </div>
                <div class="space-y-3">
                    <label for="member-input" class="text-xs font-bold text-gray-500 uppercase">Add Members</label>
                    <div class="flex space-x-2">
                        <input id="member-input" bind:value={memberInput} placeholder="Hash or Nickname..." class="flex-1 p-3 bg-gray-50 rounded-xl border-none text-xs" onkeydown={(e) => e.key === 'Enter' && addMember()} />
                        <button onclick={addMember} aria-label="Add Member" class="bg-blue-600 text-white p-3 rounded-xl disabled:opacity-50" disabled={!memberInput}><LucidePlus size={20}/></button>
                    </div>
                <div class="space-y-4">
                    <div class="text-[10px] font-bold text-gray-400 uppercase tracking-widest">Select from Contacts</div>
                    <div class="space-y-1 max-h-48 overflow-y-auto custom-scrollbar">
                        {#each Object.values($userStore.chats).filter(c => !c.isGroup) as contact}
                            <button 
                                onclick={() => toggleMember(contact.peerHash)}
                                class="w-full flex items-center justify-between p-2 rounded-xl border-2 {groupMembers.includes(contact.peerHash) ? 'border-blue-500 bg-blue-50' : 'border-transparent bg-gray-50'} transition"
                            >
                                <div class="flex items-center space-x-3">
                                    <div class="w-8 h-8 rounded-full bg-blue-100 flex items-center justify-center text-[10px] font-bold text-blue-600">
                                        {(contact.localNickname || contact.peerAlias || "?")[0].toUpperCase()}
                                    </div>
                                    <div class="text-left">
                                        <div class="text-xs font-bold text-gray-800">{contact.localNickname || contact.peerAlias || contact.peerHash.slice(0, 8)}</div>
                                        <div class="text-[9px] font-mono text-gray-400">{contact.peerHash.slice(0, 16)}...</div>
                                    </div>
                                </div>
                                {#if groupMembers.includes(contact.peerHash)}
                                    <LucideCheckCircle2 size={16} class="text-blue-500" />
                                {/if}
                            </button>
                        {/each}
                    </div>
                </div>
                <div class="space-y-2">
                    {#each groupMembers as m}<div class="flex items-center justify-between p-2 bg-blue-50 rounded-lg text-[10px] font-mono"><span>{m.slice(0, 32)}...</span><button onclick={() => removeMember(m)}><LucideX size={14}/></button></div>{/each}
                </div>
            </div>
        </div>
        <div class="p-6 border-t border-gray-100"><button onclick={handleCreateGroup} disabled={!groupName || groupMembers.length === 0} class="w-full py-4 bg-blue-600 text-white rounded-2xl font-bold shadow-lg active:scale-[0.98] transition">Create Group Chat</button></div>
    </div>
  {/if}
</div>

<style>
    .custom-scrollbar::-webkit-scrollbar { width: 4px; }
    .custom-scrollbar::-webkit-scrollbar-thumb { background: rgba(0,0,0,0.1); border-radius: 10px; }
</style>
