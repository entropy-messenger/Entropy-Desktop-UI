
<script lang="ts">
  import { LucidePlay, LucidePause, LucideMic } from 'lucide-svelte';
  import { onMount } from 'svelte';
  import { playingVoiceNoteId } from '../lib/stores/audio';

  let { src, id, isMine = false } = $props();

  let audioEl = $state<HTMLAudioElement | null>(null);
  let canvasEl = $state<HTMLCanvasElement | null>(null);
  let isPlaying = $state(false);
  let currentTime = $state(0);
  let duration = $state(0);
  let playbackSpeed = $state(1);
  let waveformData = $state<number[]>([]);
  const speeds = [0.5, 1, 1.5, 2];

  async function generateWaveform() {
    if (!src) return;
    try {
      const response = await fetch(src);
      const arrayBuffer = await response.arrayBuffer();
      const audioCtx = new (window.AudioContext || (window as any).webkitAudioContext)();
      const audioBuffer = await audioCtx.decodeAudioData(arrayBuffer);
      
      const rawData = audioBuffer.getChannelData(0);
      const samples = 40; // Fewer bars for smaller UI
      const blockSize = Math.floor(rawData.length / samples);
      const result = [];
      
      for (let i = 0; i < samples; i++) {
        let blockStart = blockSize * i;
        let sum = 0;
        for (let j = 0; j < blockSize; j++) {
          sum = sum + Math.abs(rawData[blockStart + j]);
        }
        result.push(sum / blockSize);
      }
      
      const max = Math.max(...result);
      waveformData = result.map(n => n / max);
      drawWaveform();
    } catch (e) {
      console.error("Waveform generation failed:", e);
    }
  }

  function drawWaveform() {
    if (!canvasEl || waveformData.length === 0) return;
    const ctx = canvasEl.getContext('2d');
    if (!ctx) return;

    const width = canvasEl.width;
    const height = canvasEl.height;
    const padding = 2;
    const barWidth = (width / waveformData.length) - padding;
    
    ctx.clearRect(0, 0, width, height);
    
    waveformData.forEach((val, i) => {
      const x = i * (barWidth + padding);
      const barHeight = Math.max(2, val * height * 0.7);
      const y = (height - barHeight) / 2;
      
      const progress = currentTime / (duration || 1);
      const isPlayed = (i / waveformData.length) < progress;
      
      if (isPlayed) {
        ctx.fillStyle = isMine ? '#0a0a0a' : '#2563eb';
      } else {
        ctx.fillStyle = isMine ? 'rgba(0,0,0,0.1)' : 'rgba(37, 99, 235, 0.15)';
      }
      
      const radius = 1;
      ctx.beginPath();
      ctx.roundRect(x, y, barWidth, barHeight, radius);
      ctx.fill();
    });
  }

  function togglePlay() {
    if (!audioEl) return;
    if (isPlaying) {
      audioEl.pause();
      isPlaying = false;
      playingVoiceNoteId.set(null);
    } else {
      playingVoiceNoteId.set(id);
      audioEl.play();
      isPlaying = true;
    }
  }

  // Effect to handle exclusive playback using reactive store value
  $effect(() => {
      const currentId = $playingVoiceNoteId;
      // If something else is playing or nothing is playing (global stop), pause this one
      if (currentId !== id && isPlaying) {
          if (audioEl) {
              audioEl.pause();
          }
          isPlaying = false;
      }
  });

  function toggleSpeed() {
    if (!audioEl) return;
    const currentIndex = speeds.indexOf(playbackSpeed);
    const nextIndex = (currentIndex + 1) % speeds.length;
    playbackSpeed = speeds[nextIndex];
    audioEl.playbackRate = playbackSpeed;
  }

  function handleTimeUpdate() {
    if (audioEl) {
      currentTime = audioEl.currentTime;
      drawWaveform();
    }
  }

  function handleMetadata() {
    if (audioEl) duration = audioEl.duration;
  }

  function handleSeek(e: MouseEvent) {
    if (!canvasEl || !audioEl) return;
    const rect = canvasEl.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const progress = x / rect.width;
    audioEl.currentTime = progress * (duration || 0);
    currentTime = audioEl.currentTime;
    drawWaveform();
  }

  function formatTime(s: number) {
    if (!s || isNaN(s)) return "0:00";
    const mins = Math.floor(s / 60);
    const secs = Math.floor(s % 60);
    return `${mins}:${secs.toString().padStart(2, '0')}`;
  }

  onMount(() => {
    generateWaveform();
    return () => {
      if (audioEl) audioEl.pause();
    };
  });

  $effect(() => {
    if (src) generateWaveform();
  });
</script>

<div class="flex items-center space-x-2 py-1 px-1 min-w-[220px] select-none rounded-xl transition-all {isPlaying ? 'bg-white/10 ring-1 ring-inset ring-white/5' : ''}">
  <button 
    onclick={togglePlay}
    class="w-9 h-9 shrink-0 rounded-full flex items-center justify-center transition-all {isMine ? 'bg-black text-black bg-opacity-10 hover:bg-opacity-20' : 'bg-blue-500 text-blue-500 bg-opacity-10 hover:bg-opacity-20'}"
  >
    {#if isPlaying}
      <LucidePause size={18} fill="currentColor" />
    {:else}
      <LucidePlay size={18} fill="currentColor" class="translate-x-0.5" />
    {/if}
  </button>

  <div class="flex-1 space-y-0.5 min-w-0">
      <div 
        class="relative h-7 w-full cursor-pointer flex items-center" 
        onclick={handleSeek}
        onkeypress={(e) => e.key === 'Enter' && togglePlay()}
        role="button"
        tabindex="0"
      >
          <canvas 
            bind:this={canvasEl} 
            width="160" 
            height="32" 
            class="w-full h-full"
          ></canvas>
      </div>
      <div class="flex justify-between items-center px-0.5">
          <div class="flex items-center space-x-1.5 overflow-hidden">
              <span class="text-[9px] font-bold opacity-50 {isMine ? 'text-black' : 'text-blue-600'} whitespace-nowrap">
                  {formatTime(isPlaying ? currentTime : duration)}
              </span>
          </div>
          <LucideMic size={10} class="opacity-30 {isPlaying ? 'text-blue-500 opacity-100' : ''}" />
      </div>
  </div>

  <button 
    onclick={toggleSpeed}
    class="shrink-0 px-1.5 py-1 rounded-md text-[9px] font-black transition-colors {isMine ? 'bg-black/10 hover:bg-black/20 text-black' : 'bg-blue-500/10 hover:bg-blue-500/20 text-blue-600'}"
  >
    {playbackSpeed}x
  </button>

  <audio 
    bind:this={audioEl} 
    src={src} 
    ontimeupdate={handleTimeUpdate} 
    onloadedmetadata={handleMetadata}
    onended={() => { isPlaying = false; currentTime = 0; playingVoiceNoteId.set(null); drawWaveform(); }}
    hidden
  ></audio>
</div>

<style>
  canvas {
    image-rendering: crisp-edges;
  }
</style>
