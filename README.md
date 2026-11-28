<div align="center">

# 🛡️ SimpleWarnAnalyzer

**Helps analyze the computer's most vulnerable areas.**

<a href="https://github.com/user110611/SimpleWarnAnalyzer/stargazers"><img alt="Stars" src="https://img.shields.io/github/stars/user110611/SimpleWarnAnalyzer?style=for-the-badge&logo=github&labelColor=0d1117&color=f5c542"></a> <a href="https://github.com/user110611/SimpleWarnAnalyzer/forks"><img alt="Forks" src="https://img.shields.io/github/forks/user110611/SimpleWarnAnalyzer?style=for-the-badge&logo=github&labelColor=0d1117&color=58a6ff"></a> <a href="https://github.com/user110611/SimpleWarnAnalyzer/issues"><img alt="Issues" src="https://img.shields.io/github/issues/user110611/SimpleWarnAnalyzer?style=for-the-badge&logo=github&labelColor=0d1117&color=f85149"></a> <a href="https://github.com/user110611/SimpleWarnAnalyzer/releases"><img alt="Downloads" src="https://img.shields.io/github/downloads/user110611/SimpleWarnAnalyzer/total?style=for-the-badge&logo=github&labelColor=0d1117&color=3fb950"></a>

<a href="https://github.com/user110611/SimpleWarnAnalyzer/releases/latest"><img alt="Release" src="https://img.shields.io/github/v/release/user110611/SimpleWarnAnalyzer?style=flat-square&labelColor=0d1117&color=8957e5"></a> <img alt="Platform" src="https://img.shields.io/badge/platform-Windows-0078d4?style=flat-square&labelColor=0d1117&logo=windows"> <img alt="Open source" src="https://img.shields.io/badge/open%20source-100%25-3fb950?style=flat-square&labelColor=0d1117"> <img alt="Languages" src="https://img.shields.io/badge/lang-RU%20%7C%20EN%20%7C%20IT-f0883e?style=flat-square&labelColor=0d1117">

**English** · [Русский](README.ru.md) · [Italiano](README.it.md)

</div>

A single-file Windows scanner (no installer, no cloud, no telemetry) that collects, in a few seconds, every place malware likes to hide and tells you **what to do about it in plain language**.

## Why it is different

- **One screen, one answer.** The Home page says "All good" or "Needs checking", lists the 5 most important issues and puts the recommended action under each one. No expert knowledge needed.
- **Explains instead of scaring.** Every finding comes with the reasons behind its 0–100 risk score (unsigned file, runs from Temp, hidden window, tampered Winlogon…). Signed Microsoft files and your whitelist are not flagged.
- **Everything where malware persists.** Run / RunOnce (user, system, WOW64, policies), Winlogon, Startup folders, Task Scheduler, Active Setup, IFEO, AppInit_DLLs, services, processes, network connections, hosts file, and a deep file search in Temp / AppData / ProgramData / Downloads.
- **Reversible.** Quarantine with one-click restore, a journal of every action with timestamps and an **Undo** button, a safety copy of `hosts` before each edit.
- **Windows Defender built in (optional).** See Defender threats and status, mark them as read, scan a file, and manage exclusions and protected folders.
- **Editable hosts file.** Add, edit or remove entries safely, with automatic backups.
- **What changed since last time.** New and disappeared startup items between scans, "first seen" timestamps.
- **Private by design.** Runs a tiny web UI on `127.0.0.1` only, protected by a per-run token. Your data never leaves your PC; the only internet request is an optional update check against GitHub (can be turned off in Settings).
- **Update notice.** A green banner at the top appears when a newer release is published, with buttons for GitHub, direct download, "don't show again" and close.
- **Three languages.** Russian, English and Italian, switchable in the header (English by default).

> It is a heuristic helper, not a replacement for a full antivirus. Treat "Suspicious" as "worth a look", not as a verdict.

## Run

Download `SimpleWarnAnalyzer.exe` from the [Releases](../../releases) page and start it — your browser opens `http://127.0.0.1:8787`. For full access run it as administrator.

```
SimpleWarnAnalyzer.exe                 # web interface
SimpleWarnAnalyzer.exe --console       # legacy console menu
SimpleWarnAnalyzer.exe --no-open --port 8787
```

Your data (archive, journal, whitelist, settings) lives in the `Данные` ("Data") folder next to the exe.

## FAQ

**How do I quickly check my Windows PC for malware?**
Download `SimpleWarnAnalyzer.exe` from [Releases](../../releases/latest), run it (as administrator for full access) and read the Home page: it answers "All good" or "Needs checking" within seconds and shows what to do about each finding.

**How can I see what starts with Windows and what is connecting to the internet?**
The scanner lists every autostart location (Run/RunOnce, Winlogon, Startup folders, Task Scheduler, services, IFEO, AppInit_DLLs) and all active network connections with the owning process.

**Is there a free portable malware scanner that needs no installation?**
Yes: SimpleWarnAnalyzer is a single `.exe`, MIT-licensed, with no installer, no cloud and no telemetry.

**How do I check or repair the Windows hosts file?**
Open the Hosts page: entries can be added, edited or removed, and a backup is made automatically before each change.

**Does it replace antivirus software?**
No. It is a heuristic helper and a second opinion that works alongside Windows Defender.

**Is it safe and private?**
It is fully open source, listens only on `127.0.0.1` with a per-run token, and sends nothing anywhere; the only optional request is an update check against GitHub.

## Build

You need g++ (MSYS2 / MinGW-w64):

```
build.bat                     # or: powershell -File build.ps1 [-Out name.exe]
```

`ui.html` is embedded into the exe at build time. If `ui.html` lies next to the exe it is used instead — handy for editing the UI without rebuilding.

## License

See [LICENSE](LICENSE).
