
import { writable } from 'svelte/store';

export const playingVoiceNoteId = writable<string | null>(null);
