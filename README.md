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
- **Private by design.** Runs a tiny web UI on `127.0.0.1` only, protected by a per-run token. Nothing leaves your PC.
- **Three languages.** Russian, English and Italian, switchable in the header (auto-detected on first run).

> It is a heuristic helper, not a replacement for a full antivirus. Treat "Suspicious" as "worth a look", not as a verdict.

## Run

Download `SySscaner.exe` from the [Releases](../../releases) page and start it — your browser opens `http://127.0.0.1:8787`. For full access run it as administrator.

```
SySscaner.exe                 # web interface
SySscaner.exe --console       # legacy console menu
SySscaner.exe --no-open --port 8787
```

Your data (archive, journal, whitelist, settings) lives in the `Данные` ("Data") folder next to the exe.

## Build

You need g++ (MSYS2 / MinGW-w64):

```
build.bat                     # or: powershell -File build.ps1 [-Out name.exe]
```

`ui.html` is embedded into the exe at build time. If `ui.html` lies next to the exe it is used instead — handy for editing the UI without rebuilding.

## License

See [LICENSE](LICENSE).
