
<script lang="ts">
  import { onMount } from 'svelte';
  import { userStore } from './lib/stores/user';
  import { createIdentity, initApp } from './lib/store';
  import { network } from './lib/network';
  import Sidebar from './components/Sidebar.svelte';
  import ChatWindow from './components/ChatWindow.svelte';
  import CallOverlay from './components/CallOverlay.svelte';
  import TitleBar from './components/TitleBar.svelte';
  import { LucideWifiOff, LucideShieldCheck, LucideLock, LucideFingerprint } from 'lucide-svelte';
  import { invoke } from '@tauri-apps/api/core';
  import { isPermissionGranted, requestPermission } from '@tauri-apps/plugin-notification';

  let password = $state("");
  let isInitializing = $state(true);
  let hasExistingIdentity = $state(false);

  import { hasStoredSalt } from './lib/secure_storage';

  const checkNotificationPermission = async () => {
    let permission = await isPermissionGranted();
    if (!permission) {
      permission = await requestPermission() === 'granted';
    }
  };

  onMount(async () => {
    
    if (window.__TAURI_INTERNALS__) {
        await new Promise(r => setTimeout(r, 100));
    }
    
    isInitializing = false;
    hasExistingIdentity = await hasStoredSalt();

    if (window.__TAURI_INTERNALS__) {
      try {
        await checkNotificationPermission();
      } catch (e) {
        console.error("Tauri permission failed:", e);
      }
    }
  });

  const handleLogin = async () => {
    if (!password) return;
    isInitializing = true;
    try {
        await initApp(password);
    } catch (e: any) {
        console.error("Login component caught error:", e);
    } finally {
        isInitializing = false;
    }
  };

  const handleCreate = async () => {
    if (!password) return;
    isInitializing = true;
    try {
        await createIdentity(password);
        network.connect();
    } catch (e: any) {
        alert("Creation failed: " + (e.message || e));
    } finally {
        isInitializing = false;
    }
  };

  function handleContextMenu(e: MouseEvent) {
      if (import.meta.env.DEV) return;
      e.preventDefault();
  }

  function handleKeydown(e: KeyboardEvent) {
      if (import.meta.env.DEV) return;
      if (
          e.key === 'F12' ||
          (e.ctrlKey && e.shiftKey && (e.key === 'I' || e.key === 'J' || e.key === 'C'))
      ) {
          e.preventDefault();
      }
  }

    async function handleNuclearReset() {
        if (!confirm("This will PERMANENTLY delete your vault and all messages. Are you sure?")) return;
        try {
            await invoke('nuclear_reset');
            localStorage.clear();
            window.location.reload();
        } catch (e) {
            alert("Reset failed: " + e);
        }
    }

    import { signalManager } from './lib/signal_manager';

    async function handleExport() {
        try {
            const data = await signalManager.exportIdentity();
            const blob = new Blob([data as any], { type: 'application/octet-stream' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `entropy_identity_${new Date().toISOString().split('T')[0]}.entropy`;
            a.click();
            URL.revokeObjectURL(url);
        } catch (e) {
            alert("Export failed: " + e);
        }
    }

    async function handleImport() {
        const input = document.createElement('input');
        input.type = 'file';
        input.accept = '.entropy,.json';
        input.onchange = async (e: any) => {
            const file = e.target.files[0];
            const reader = new FileReader();
            reader.onload = async () => {
                try {
                    const data = new Uint8Array(reader.result as ArrayBuffer);
                    await signalManager.importIdentity(data);
                    alert("Identity imported! The app will now reload.");
                    window.location.reload();
                } catch (err) {
                    alert("Import failed: " + err);
                }
            };
            reader.readAsArrayBuffer(file);
        };
        input.click();
    }
</script>

<svelte:window oncontextmenu={handleContextMenu} onkeydown={handleKeydown} />

<main class="h-screen w-screen bg-gray-50 overflow-hidden flex flex-col font-sans antialiased text-gray-900 select-none">
    
    {#if !$userStore.identityHash}
        
        <div class="flex-1 flex items-center justify-center bg-[#f8fafc] relative overflow-hidden">
            
            <div class="absolute inset-0 pointer-events-none">
                <div class="absolute top-[-20%] left-[-10%] w-[60%] h-[60%] bg-blue-400/10 blur-[150px] rounded-full animate-pulse"></div>
                <div class="absolute bottom-[-20%] right-[-10%] w-[60%] h-[60%] bg-indigo-400/10 blur-[150px] rounded-full animate-pulse" style="animation-delay: 2s;"></div>
                <div class="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[30%] h-[30%] bg-purple-400/5 blur-[100px] rounded-full"></div>
            </div>

            <div class="bg-white/80 backdrop-blur-xl rounded-[3rem] shadow-[0_40px_100px_-20px_rgba(0,0,0,0.1)] w-[440px] text-center overflow-hidden animate-in zoom-in-95 duration-700 border border-white relative z-10">
                <TitleBar />
                <div class="p-12 space-y-10">
                    <div class="relative inline-block">
                        <div class="w-20 h-20 bg-white rounded-2xl shadow-xl flex items-center justify-center mx-auto transform -rotate-6 transition-all duration-700 hover:rotate-0 hover:scale-105 group border-2 border-gray-50">
                            <img src="/logo.png" alt="Entropy" class="w-16 h-16 object-contain transition-transform duration-500 group-hover:scale-110" />
                        </div>
                        <div class="absolute -top-1.5 -right-1.5 bg-blue-600 text-white p-1.5 rounded-xl shadow-lg border border-white">
                            <LucideShieldCheck size={14} />
                        </div>
                    </div>
                    
                    <div class="space-y-3">
                        <h1 class="text-4xl font-[900] text-gray-900 tracking-tighter">Entropy</h1>
                        <p class="text-gray-500 text-sm leading-relaxed max-w-[280px] mx-auto font-medium">
                            {hasExistingIdentity 
                                ? 'Your cryptographic vault is locked. Please enter your master password.' 
                                : 'Privacy by design, not by policy. Create your first decentralized identity.'}
                        </p>
                    </div>
                    
                    <div class="space-y-6 text-left">
                        <div class="space-y-2.5">
                            <div class="flex justify-between items-center px-1">
                                <label for="vault-password" class="text-[10px] font-black text-gray-400 uppercase tracking-widest pl-1">Master Password</label>
                                {#if hasExistingIdentity}
                                    <span class="text-[10px] font-bold text-blue-600 uppercase tracking-tight">Identity Found</span>
                                {/if}
                            </div>
                            
                            {#if $userStore.authError}
                                <div class="p-4 bg-red-50 border border-red-100/50 rounded-2xl text-[11px] font-bold text-red-600 animate-in fade-in slide-in-from-top-2 flex items-center space-x-2">
                                    <div class="w-1.5 h-1.5 bg-red-500 rounded-full animate-pulse"></div>
                                    <span>{$userStore.authError}</span>
                                </div>
                            {/if}

                            <div class="relative group">
                                <div class="absolute left-5 top-1/2 -translate-y-1/2 text-gray-300 group-focus-within:text-blue-500 transition-colors">
                                    <LucideLock size={18} />
                                </div>
                                <input 
                                    id="vault-password"
                                    type="password" 
                                    bind:value={password}
                                    placeholder="••••••••••••" 
                                    class="w-full pl-14 pr-6 py-5 bg-gray-50/50 rounded-[1.5rem] border-2 border-transparent focus:border-blue-500/20 focus:bg-white focus:ring-4 focus:ring-blue-500/5 transition-all text-lg font-mono tracking-[0.4em] outline-none {$userStore.authError ? 'border-red-500/20' : ''}"
                                    onkeydown={(e) => e.key === 'Enter' && handleLogin()}
                                />
                            </div>
                        </div>

                        {#if hasExistingIdentity}
                            <button 
                                class="w-full py-5 bg-blue-600 text-white rounded-[1.5rem] font-black text-sm uppercase tracking-widest hover:bg-blue-700 transition-all shadow-xl shadow-blue-600/20 active:scale-[0.98] disabled:opacity-50 flex items-center justify-center space-x-3 overflow-hidden group"
                                onclick={handleLogin}
                                disabled={isInitializing || !password}
                                aria-label="Unlock Identity"
                            >
                                {#if isInitializing}
                                    <div class="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin"></div>
                                    <span>Unlocking Vault...</span>
                                {:else}
                                    <LucideFingerprint size={20} class="group-hover:scale-110 transition-transform" />
                                    <span>Unlock Identity</span>
                                {/if}
                            </button>
                        {:else}
                            <button 
                                class="w-full py-5 bg-gray-900 text-white rounded-[1.5rem] font-black text-sm uppercase tracking-widest hover:bg-black transition-all shadow-2xl active:scale-[0.98] disabled:opacity-50 flex items-center justify-center space-x-3 overflow-hidden group"
                                onclick={handleCreate}
                                disabled={isInitializing || !password}
                                aria-label="Create Secure Identity"
                            >
                                {#if isInitializing}
                                    <div class="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin"></div>
                                    <span>Generating Seed...</span>
                                {:else}
                                    <LucideShieldCheck size={20} class="group-hover:scale-110 transition-transform" />
                                    <span>Create Secure Identity</span>
                                {/if}
                            </button>
                        {/if}
                    </div>

                    <div class="pt-2 space-y-4">
                        <p class="text-[10px] text-gray-400 font-bold uppercase tracking-[0.2em] italic">Zero-Knowledge Architecture</p>
                        
                        <div class="flex items-center justify-center space-x-4 pt-4">
                            {#if hasExistingIdentity}
                                <button 
                                    onclick={handleExport}
                                    class="text-[10px] font-black text-blue-400 uppercase tracking-widest hover:text-blue-600 transition-colors"
                                >
                                    Backup Identity
                                </button>
                            {/if}
                            <button 
                                onclick={handleImport}
                                class="text-[10px] font-black text-indigo-400 uppercase tracking-widest hover:text-indigo-600 transition-colors"
                            >
                                Restore Identity
                            </button>
                            {#if import.meta.env.DEV || $userStore.authError}
                                <button 
                                    onclick={handleNuclearReset}
                                    class="text-[10px] font-black text-red-300 uppercase tracking-widest hover:text-red-500 transition-colors"
                                >
                                    Wipe
                                </button>
                            {/if}
                        </div>
                    </div>
                </div>
            </div>
        </div>
    {:else}
        
        <TitleBar />
        <div class="flex flex-row flex-1 overflow-hidden bg-white">
            <Sidebar />
            <div class="flex-1 relative flex flex-col min-w-0">
                <ChatWindow />
            
                {#if $userStore.connectionStatus !== 'connected'}
                    <div class="absolute inset-0 bg-white/60 backdrop-blur-sm z-50 flex items-center justify-center animate-in fade-in duration-500">
                        <div class="bg-white p-10 rounded-[2.5rem] shadow-[0_40px_100px_-20px_rgba(0,0,0,0.15)] border border-gray-100 flex flex-col items-center space-y-8 max-w-sm text-center relative overflow-hidden">
                            <div class="absolute top-0 left-0 w-full h-1 bg-gray-100">
                                <div class="h-full bg-blue-600 animate-progress"></div>
                            </div>
                            
                            {#if $userStore.connectionStatus === 'mining'}
                                <div class="relative">
                                    <div class="w-20 h-20 border-4 border-blue-600/10 border-t-blue-600 rounded-full animate-spin"></div>
                                    <div class="absolute inset-0 flex items-center justify-center text-blue-600">
                                        <LucideShieldCheck size={32} />
                                    </div>
                                </div>
                                <div class="space-y-2">
                                    <div class="text-xl font-black text-gray-900 tracking-tight">Securing Session</div>
                                    <div class="text-[12px] text-gray-500 font-medium leading-relaxed px-4">Computing cryptographic proof to protect your identity. This only happens once per session.</div>
                                </div>
                            {:else if $userStore.connectionStatus === 'connecting'}
                                <div class="w-20 h-20 border-4 border-indigo-600/10 border-t-indigo-600 rounded-full animate-spin"></div>
                                <div class="space-y-2">
                                    <div class="text-xl font-black text-gray-900 tracking-tight">Verifying Identity</div>
                                    <div class="text-[12px] text-gray-500 font-medium px-4">
                                        {$userStore.sessionToken ? 'Validating session token with relay...' : 'Handshaking with Entropy relay nodes...'}
                                    </div>
                                </div>
                            {:else}
                                <div class="w-20 h-20 bg-amber-50 rounded-full flex items-center justify-center text-amber-500 animate-pulse">
                                    <LucideWifiOff size={40} />
                                </div>
                                <div class="space-y-2">
                                    <div class="text-xl font-black text-gray-900 tracking-tight">Reconnecting</div>
                                    <div class="text-[12px] text-gray-500 font-medium px-4">The secure link was interrupted. Attempting to re-establish the connection...</div>
                                </div>
                            {/if}
                        </div>
                    </div>
                {/if}
            </div>
        </div>
        <CallOverlay />
    {/if}

</main>

<style>
    :global(body) {
        background-color: transparent;
        margin: 0;
        padding: 0;
        user-select: none;
        cursor: default;
        -webkit-user-select: none;
        overflow: hidden;
    }

    @keyframes progress {
        0% { width: 0%; left: 0%; }
        50% { width: 100%; left: 0%; }
        100% { width: 0%; left: 100%; }
    }

    .animate-progress {
        animation: progress 2s infinite ease-in-out;
    }
</style>
