/*
 * Vencord, a Discord client mod
 * Copyright (c) 2026 Vendicated and contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { definePluginSettings } from "@api/Settings";
// @ts-ignore
import { xsalsa20poly1305 } from "@noble/ciphers/salsa.js";
// @ts-ignore
import { x25519 } from "@noble/curves/ed25519.js";
import definePlugin, { OptionType } from "@utils/types";
import { findByProps, findStore } from "@webpack";
import { React } from "@webpack/common";

let MessageActions: any;
let Dispatcher: any;
let ChannelStore: any;
let UserStore: any;
let MessageStore: any;
let SelectedChannelStore: any;
let UserProfileFetchUtils: any;
let UserProfileStore: any;

let myKeyPair: { secretKey: Uint8Array, publicKey: Uint8Array; } | null = null;
let myPublicKeyBase64: string = "";
const pubKeyCache = new Map<string, Uint8Array>();
const symmetricKeyCache = new Map<string, Uint8Array>();

let origSendMessage: Function | null = null;
let origDispatch: Function | null = null;

function encodeBase64(arr: Uint8Array): string {
    let binary = "";
    const len = arr.byteLength;
    for (let i = 0; i < len; i++) binary += String.fromCharCode(arr[i]);
    return window.btoa(binary);
}

function decodeBase64(b64: string): Uint8Array {
    const binary = window.atob(b64);
    const len = binary.length;
    const arr = new Uint8Array(len);
    for (let i = 0; i < len; i++) arr[i] = binary.charCodeAt(i);
    return arr;
}

function evaluatePasswordStrength(password: string): { valid: boolean, message: string, color: string; } {
    if (!password) return { valid: false, message: "Enter a password to generate keys.", color: "var(--text-muted)" };
    if (password.length < 12) return { valid: false, message: "Too short (minimum 12 characters).", color: "var(--text-danger)" };
    if (!/[A-Z]/.test(password)) return { valid: false, message: "Needs at least one uppercase letter.", color: "var(--text-danger)" };
    if (!/[a-z]/.test(password)) return { valid: false, message: "Needs at least one lowercase letter.", color: "var(--text-danger)" };
    if (!/[0-9]/.test(password)) return { valid: false, message: "Needs at least one number.", color: "var(--text-danger)" };
    if (!/[^A-Za-z0-9]/.test(password)) return { valid: false, message: "Needs at least one special character.", color: "var(--text-danger)" };

    return { valid: true, message: "Strong password! Keys generated successfully.", color: "var(--text-positive)" };
}

async function deriveKeyFromPassword(password: string): Promise<Uint8Array> {
    const enc = new TextEncoder();
    const keyMaterial = await window.crypto.subtle.importKey(
        "raw",
        enc.encode(password),
        { name: "PBKDF2" },
        false,
        ["deriveBits"]
    );

    const salt = enc.encode("f4NkHv(lxeU5awKmfRHWd#ZZoZFb7lvR");

    const derivedBits = await window.crypto.subtle.deriveBits(
        {
            name: "PBKDF2",
            salt,
            iterations: 250000,
            hash: "SHA-256"
        },
        keyMaterial,
        256
    );

    return new Uint8Array(derivedBits);
}

let latestPasswordAttempt = "";
async function updateKeyPair(password: string) {
    latestPasswordAttempt = password;
    const strength = evaluatePasswordStrength(password);

    if (!strength.valid) {
        myKeyPair = null;
        myPublicKeyBase64 = "";
        pubKeyCache.clear();
        symmetricKeyCache.clear();
        return;
    }

    try {
        const secretKey = await deriveKeyFromPassword(password);

        if (latestPasswordAttempt !== password) return;

        myKeyPair = { secretKey, publicKey: x25519.getPublicKey(secretKey) };
        myPublicKeyBase64 = encodeBase64(myKeyPair.publicKey);
        pubKeyCache.clear();
        symmetricKeyCache.clear();
    } catch (err) {
        console.error("[LoveCipher] Failed to derive key from password", err);
    }
}

async function getPublicKey(userId: string): Promise<Uint8Array | null> {
    if (pubKeyCache.has(userId)) return pubKeyCache.get(userId)!;

    if (!UserProfileFetchUtils) UserProfileFetchUtils = findByProps("fetchProfile");
    if (!UserProfileStore) UserProfileStore = findStore("UserProfileStore");

    try {
        let profile = UserProfileStore?.getUserProfile(userId);
        if (!profile && UserProfileFetchUtils?.fetchProfile) {
            await UserProfileFetchUtils.fetchProfile(userId);
            profile = UserProfileStore?.getUserProfile(userId);
        }

        if (profile?.bio) {
            const match = profile.bio.match(/E2EE:([A-Za-z0-9+/=]+)/);
            if (match) {
                const pubKey = decodeBase64(match[1]);
                pubKeyCache.set(userId, pubKey);
                return pubKey;
            }
        }
    } catch (err) { }

    return null;
}

async function getSymmetricKey(userId: string): Promise<Uint8Array | null> {
    if (symmetricKeyCache.has(userId)) return symmetricKeyCache.get(userId)!;

    const pubKey = await getPublicKey(userId);
    if (!pubKey || !myKeyPair) return null;

    const sharedSecret = x25519.getSharedSecret(myKeyPair.secretKey, pubKey);
    const hash = await window.crypto.subtle.digest("SHA-256", sharedSecret as any);
    const symKey = new Uint8Array(hash);

    symmetricKeyCache.set(userId, symKey);
    return symKey;
}

async function encryptMessage(content: string, recipientId: string, channelId: string): Promise<string> {
    if (!myKeyPair) return content;

    const symKey = await getSymmetricKey(recipientId);
    if (!symKey) return content;

    try {
        const payloadStr = JSON.stringify({ c: channelId, m: content });
        const payloadBytes = new TextEncoder().encode(payloadStr);

        const nonce = new Uint8Array(24);
        window.crypto.getRandomValues(nonce);

        const encrypted = xsalsa20poly1305(symKey, nonce).encrypt(payloadBytes);

        const finalPayload = new Uint8Array(nonce.length + encrypted.length);
        finalPayload.set(nonce);
        finalPayload.set(encrypted, nonce.length);

        return `[E2EEv2]${encodeBase64(finalPayload)}`;
    } catch (err) {
        return content;
    }
}

function decryptMessage(content: string, symKey: Uint8Array, channelId: string): string {
    try {
        const b64 = content.slice(8);
        const payload = decodeBase64(b64);
        const nonce = payload.slice(0, 24);
        const ciphertext = payload.slice(24);

        const decryptedBytes = xsalsa20poly1305(symKey, nonce).decrypt(ciphertext);
        const decryptedStr = new TextDecoder().decode(decryptedBytes);

        const parsed = JSON.parse(decryptedStr);

        if (parsed.c !== channelId) {
            return "🔒 [LoveCipher] Context mismatch (Replay attack detected).";
        }

        return parsed.m;
    } catch (err) {
        return content;
    }
}

async function processMessage(msg: any) {
    if (!msg || typeof msg.content !== "string" || !msg.content.startsWith("[E2EEv2]")) return;

    let otherPartyId: string | null = null;
    const channel = ChannelStore?.getChannel(msg.channel_id);

    if (channel && channel.type === 1 && channel.recipients?.length > 0) {
        otherPartyId = channel.recipients[0];
    } else return;

    if (otherPartyId) {
        const originalContent = msg.content;
        const symKey = await getSymmetricKey(otherPartyId);

        if (symKey) {
            const decrypted = decryptMessage(originalContent, symKey, msg.channel_id);
            if (decrypted !== originalContent) {
                msg.content = decrypted;
                const msgRecord = MessageStore?.getMessage(msg.channel_id, msg.id);
                if (msgRecord) msgRecord.content = decrypted;

                if (Dispatcher && origDispatch) {
                    setTimeout(() => {
                        origDispatch!.call(Dispatcher, {
                            type: "MESSAGE_UPDATE",
                            message: { id: msg.id, channel_id: msg.channel_id, content: decrypted }
                        });
                    }, 0);
                }
            }
        }
    }
}

const settings = definePluginSettings({
    password: {
        type: OptionType.STRING,
        description: "Master Password",
        default: "",
        onChange: (value: string) => updateKeyPair(value)
    }
});

function SettingsAbout() {
    const { password } = settings.use(["password"]);
    const strength = evaluatePasswordStrength(password);

    const [localPubKey, setLocalPubKey] = React.useState("");
    const [isGenerating, setIsGenerating] = React.useState(false);

    React.useEffect(() => {
        if (!strength.valid) {
            setLocalPubKey("");
            setIsGenerating(false);
            return;
        }

        setIsGenerating(true);
        deriveKeyFromPassword(password).then(secretKey => {
            const pub = x25519.getPublicKey(secretKey);
            setLocalPubKey(encodeBase64(pub));
            setIsGenerating(false);
        });
    }, [password, strength.valid]);

    return React.createElement(
        "div",
        { style: { marginTop: "16px", padding: "16px", background: "var(--background-secondary-alt)", borderRadius: "8px", border: "1px solid var(--border-subtle)" } },

        React.createElement("div", { style: { marginBottom: "16px" } },
            React.createElement("h3", { style: { color: "var(--header-primary)", marginBottom: "4px", fontWeight: "bold" } }, "Password Strength"),
            React.createElement("span", { style: { color: strength.color, fontWeight: "500", fontSize: "14px" } }, strength.message)
        ),

        React.createElement("div", null,
            React.createElement("h3", { style: { color: "var(--header-primary)", marginBottom: "8px", fontWeight: "bold" } }, "Your Public Key (Add to your Bio)"),
            React.createElement("div", {
                style: {
                    padding: "12px",
                    background: strength.valid ? "var(--background-primary)" : "var(--background-modifier-invalid)",
                    borderRadius: "6px",
                    fontFamily: "monospace",
                    userSelect: "all",
                    color: strength.valid ? "var(--text-normal)" : "var(--text-danger)",
                    wordBreak: "break-all",
                    border: strength.valid ? "1px solid var(--border-strong)" : "1px solid var(--text-danger)",
                    transition: "all 0.2s ease"
                }
            }, isGenerating ? "Generating..." : (strength.valid && localPubKey ? `E2EE:${localPubKey}` : "Awaiting valid password..."))
        )
    );
}

export default definePlugin({
    name: "LoveCipher",
    description: "Client-side End-to-End Encryption",
    authors: [{
        name: "lol123love",
        id: 693952823519346728n
    }],
    settings,
    settingsAboutComponent: SettingsAbout,

    async start() {
        MessageActions = findByProps("sendMessage");
        Dispatcher = findByProps("dispatch", "subscribe");
        ChannelStore = findStore("ChannelStore");
        UserStore = findStore("UserStore");
        MessageStore = findStore("MessageStore");
        SelectedChannelStore = findStore("SelectedChannelStore");

        await updateKeyPair(settings.store.password);

        const currentChannelId = SelectedChannelStore.getChannelId();
        if (currentChannelId) {
            const messages = MessageStore.getMessages(currentChannelId);
            if (messages && messages._array) {
                for (const msg of messages._array) processMessage(msg);
            }
        }

        if (MessageActions?.sendMessage) {
            origSendMessage = MessageActions.sendMessage;
            MessageActions.sendMessage = async function (channelId: string, message: any, ...rest: any[]) {
                if (myKeyPair && message?.content) {
                    const channel = ChannelStore?.getChannel(channelId);
                    if (channel?.type === 1 && channel.recipients?.length === 1) {
                        message.content = await encryptMessage(message.content, channel.recipients[0], channelId);
                    }
                }
                return origSendMessage!.call(this, channelId, message, ...rest);
            };
        }

        if (Dispatcher?.dispatch) {
            origDispatch = Dispatcher.dispatch;
            Dispatcher.dispatch = function (event: any) {
                try {
                    if (event.type === "MESSAGE_CREATE" || event.type === "MESSAGE_UPDATE") {
                        if (event.message) processMessage(event.message);
                    }
                    if (event.type === "LOAD_MESSAGES_SUCCESS" && Array.isArray(event.messages)) {
                        for (const msg of event.messages) processMessage(msg);
                    }
                    if (event.type === "LOCAL_MESSAGES_LOADED" && Array.isArray(event.messages)) {
                        for (const msg of event.messages) processMessage(msg);
                    }
                    if (event.type === "CHANNEL_SELECT" && event.channelId) {
                        const cachedMessages = MessageStore.getMessages(event.channelId);
                        if (cachedMessages && cachedMessages._array) {
                            cachedMessages._array.forEach((msg: any) => processMessage(msg));
                        }
                    }
                } catch (err) { }

                return origDispatch!.call(this, event);
            };
        }
    },

    stop() {
        if (MessageActions && origSendMessage) MessageActions.sendMessage = origSendMessage;
        if (Dispatcher && origDispatch) Dispatcher.dispatch = origDispatch;
        pubKeyCache.clear();
        symmetricKeyCache.clear();
    }
});
