
export const parseLinkPreview = async (text: string): Promise<any> => {
    const urlRegex = /(https?:\/\/[^\s]+)/g;
    const match = text.match(urlRegex);
    if (!match) return null;

    const url = match[0];
    try {
        const response = await fetch(url, { mode: 'no-cors' });

        return {
            url,
            title: url.replace(/https?:\/\/(www\.)?/, '').split('/')[0],
            siteName: new URL(url).hostname
        };
    } catch (e) {
        return { url, title: url, siteName: new URL(url).hostname };
    }
};

import { toHex as fastToHex, fromHex as fastFromHex } from './crypto';

export const fromHex = fastFromHex;
export const toHex = fastToHex;
