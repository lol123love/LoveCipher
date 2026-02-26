# 🔒 LoveCipher - BETA!

**LoveCipher** is a seamless, client-side End-to-End Encryption (E2EE) plugin for Vencord. It allows you to send fully encrypted messages on Discord, ensuring that nobody not even Discord themselves can read your private conversations.

⚠️ **IMPORTANT: This plugin ONLY works in 1-on-1 Direct Messages (DMs).** It does not work in Group DMs (GCs) or Server Channels.

Created with 💖 by [lol123love](https://github.com/lol123love) (`693952823519346728`).

---

## 🛠️ How to Set It Up

For LoveCipher to work, **both you and the person you are messaging must have the plugin installed and set up.**

Follow these steps exactly:

---

## Step 1: Install Requirements (Windows Only)

If you do not already have Git, Node.js, or pnpm installed, run this command in **PowerShell:**

```powershell
winget install Git.Git OpenJS.NodeJS.LTS pnpm.pnpm
```

After installation finishes, restart your terminal.

---

## Step 2: Install the Plugin

1. Clone the Vencord repository:

```bash
git clone https://github.com/Vendicated/Vencord
```

2. Download `index.ts` from this repository and place it into:

```
Vencord/src/userplugins/
```

3. Open a terminal inside the Vencord folder and run:

```bash
pnpm install
pnpm build
pnpm inject
```

---

## ✅ Done

Restart Discord and enable LoveCipher inside Vencord plugins.

Both users must have LoveCipher installed for encryption to work.
