// webmode.h — веб-режим сканера: локальный HTTP-сервер (127.0.0.1) + JSON API.
// Подключается из scan.cpp после определения u8(), expand(), Item, deleteItem().
#pragma once
#include <thread>
#include <mutex>
#include <atomic>
#include <unordered_map>
#include <map>
#include <set>
#include <algorithm>
#include <random>
#include <chrono>
#include <softpub.h>
#include <wintrust.h>
#include <mscat.h>
#include <shellapi.h>
#include <shobjidl.h>
#include <shlobj.h>
#include <bcrypt.h>
#include <iphlpapi.h>
#include <winhttp.h>

#ifndef WTD_CACHE_ONLY_URL_RETRIEVAL
#define WTD_CACHE_ONLY_URL_RETRIEVAL 0x00001000
#endif
#ifndef WTD_REVOCATION_CHECK_NONE
#define WTD_REVOCATION_CHECK_NONE 0x00000010
#endif

using std::map;
using std::set;
using std::unordered_map;

// ============================================================ утилиты
static wstring g_win, g_winOrig, g_exeDir;
static string g_token;
static int g_port = 8787;

static wstring lowerW(wstring s) { for (auto& c : s) c = (wchar_t)std::towlower(c); return s; }
static wstring trimW(const wstring& s) {
    size_t a = 0, b = s.size();
    while (a < b && std::iswspace(s[a])) a++;
    while (b > a && std::iswspace(s[b - 1])) b--;
    return s.substr(a, b - a);
}
static bool startsW(const wstring& s, const wstring& p) { return s.size() >= p.size() && s.compare(0, p.size(), p) == 0; }
static bool hasW(const wstring& s, const wchar_t* p) { return s.find(p) != wstring::npos; }
static wstring extOf(const wstring& p) {
    size_t d = p.find_last_of(L".\\/");
    if (d == wstring::npos || p[d] != L'.') return L"";
    return lowerW(p.substr(d));
}
static wstring baseName(const wstring& p) {
    size_t d = p.find_last_of(L"\\/");
    return d == wstring::npos ? p : p.substr(d + 1);
}
static bool fileExists(const wstring& p) { return GetFileAttributesW(p.c_str()) != INVALID_FILE_ATTRIBUTES; }

static string jesc(const string& s) {
    string o; o.reserve(s.size() + 8);
    for (unsigned char c : s) {
        switch (c) {
            case '"': o += "\\\""; break;
            case '\\': o += "\\\\"; break;
            case '\n': o += "\\n"; break;
            case '\r': o += "\\r"; break;
            case '\t': o += "\\t"; break;
            default:
                if (c < 0x20) { char b[8]; snprintf(b, 8, "\\u%04x", c); o += b; }
                else o += (char)c;
        }
    }
    return o;
}
static string jstr(const wstring& w) { return "\"" + jesc(u8(w)) + "\""; }

static wstring fmtTime(const FILETIME& ft) {
    FILETIME l; SYSTEMTIME st;
    if (!FileTimeToLocalFileTime(&ft, &l) || !FileTimeToSystemTime(&l, &st)) return L"";
    wchar_t b[40];
    swprintf(b, 40, L"%04d-%02d-%02d %02d:%02d", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute);
    return b;
}

static bool isElevated() {
    HANDLE t = nullptr; bool r = false;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &t)) {
        TOKEN_ELEVATION e{}; DWORD n = 0;
        if (GetTokenInformation(t, TokenElevation, &e, sizeof(e), &n)) r = e.TokenIsElevated != 0;
        CloseHandle(t);
    }
    return r;
}

// ============================================================ модель
struct WItem {
    long id = 0;
    string cat;
    wstring name, sub, detail;   // имя / подзаголовок / команда или путь
    wstring exe;                 // файл, который реально запускается (для анализа)
    wstring full;                // сам объект на диске (для показа в проводнике)
    wstring state, start;        // служба/задача
    long long size = -1;
    wstring mtime;
    bool hidden = false, isDir = false;
    DWORD pid = 0, ppid = 0;
    wstring parent;
    string sig = "none";
    int risk = 0;
    vector<string> reasons;
    string action;               // quarantine | regdel | svcdel | taskdel | kill | ""
    Item del;
    bool wl = false;             // в белом списке
    bool ack = false;            // отмечено прочитанным
    string first, ackAt;         // когда впервые замечено / когда отмечено прочитанным
    bool isnew = false;          // появилось после предыдущих сканирований этого раздела
};

static std::mutex g_storeMx;
static unordered_map<long, WItem> g_store;
static map<string, vector<long>> g_catIds;
static std::atomic<long> g_nextId{1};

// ============================================================ подписи
static std::mutex g_sigMx;
static unordered_map<wstring, int> g_sigCache;   // 0 нет, 1 есть, 2 не проверено, 3 нарушена

// подпись через каталог безопасности Windows (так подписаны почти все файлы Microsoft)
static bool verifyCatalog(const wstring& p) {
    HANDLE f = CreateFileW(p.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, 0, nullptr);
    if (f == INVALID_HANDLE_VALUE) return false;
    HCATADMIN ca = nullptr;
    bool ok = false;
    if (CryptCATAdminAcquireContext(&ca, nullptr, 0)) {
        DWORD hl = 0;
        CryptCATAdminCalcHashFromFileHandle(f, &hl, nullptr, 0);
        vector<BYTE> hash(hl ? hl : 1);
        if (hl && CryptCATAdminCalcHashFromFileHandle(f, &hl, hash.data(), 0)) {
            HCATINFO ci = CryptCATAdminEnumCatalogFromHash(ca, hash.data(), hl, 0, nullptr);
            if (ci) {
                CATALOG_INFO info{}; info.cbStruct = sizeof(info);
                if (CryptCATCatalogInfoFromContext(ci, &info, 0)) {
                    wstring tag;
                    for (DWORD i = 0; i < hl; i++) { wchar_t b[3]; swprintf(b, 3, L"%02X", hash[i]); tag += b; }
                    WINTRUST_CATALOG_INFO wc{}; wc.cbStruct = sizeof(wc);
                    wc.pcwszCatalogFilePath = info.wszCatalogFile;
                    wc.pcwszMemberTag = tag.c_str();
                    wc.pcwszMemberFilePath = p.c_str();
                    wc.hMemberFile = f;
                    wc.pbCalculatedFileHash = hash.data();
                    wc.cbCalculatedFileHash = hl;
                    wc.hCatAdmin = ca;
                    WINTRUST_DATA wd{}; wd.cbStruct = sizeof(wd);
                    wd.dwUIChoice = WTD_UI_NONE;
                    wd.fdwRevocationChecks = WTD_REVOKE_NONE;
                    wd.dwUnionChoice = WTD_CHOICE_CATALOG;
                    wd.pCatalog = &wc;
                    wd.dwStateAction = WTD_STATEACTION_VERIFY;
                    wd.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE;
                    GUID g = WINTRUST_ACTION_GENERIC_VERIFY_V2;
                    LONG r = WinVerifyTrust(nullptr, &g, &wd);
                    wd.dwStateAction = WTD_STATEACTION_CLOSE;
                    WinVerifyTrust(nullptr, &g, &wd);
                    ok = (r == 0);
                }
                CryptCATAdminReleaseCatalogContext(ca, ci, 0);
            }
        }
        CryptCATAdminReleaseContext(ca, 0);
    }
    CloseHandle(f);
    return ok;
}

static int verifySig(const wstring& p) {
    WINTRUST_FILE_INFO fi{}; fi.cbStruct = sizeof(fi); fi.pcwszFilePath = p.c_str();
    WINTRUST_DATA wd{}; wd.cbStruct = sizeof(wd);
    wd.dwUIChoice = WTD_UI_NONE;
    wd.fdwRevocationChecks = WTD_REVOKE_NONE;
    wd.dwUnionChoice = WTD_CHOICE_FILE;
    wd.pFile = &fi;
    wd.dwStateAction = WTD_STATEACTION_VERIFY;
    wd.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE;
    GUID g = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG r = WinVerifyTrust(nullptr, &g, &wd);
    wd.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &g, &wd);
    HRESULT hr = (HRESULT)r;
    if (r == 0) return 1;
    if (hr == TRUST_E_NOSIGNATURE || hr == TRUST_E_SUBJECT_FORM_UNKNOWN || hr == TRUST_E_PROVIDER_UNKNOWN)
        return verifyCatalog(p) ? 1 : 0;
    if (hr == TRUST_E_BAD_DIGEST || hr == TRUST_E_EXPLICIT_DISTRUST) return 3;
    return 2;
}

static void sigBatch(const vector<wstring>& paths) {
    vector<wstring> todo;
    {
        std::lock_guard<std::mutex> lk(g_sigMx);
        set<wstring> seen;
        for (auto& p : paths) {
            wstring lp = lowerW(p);
            if (!g_sigCache.count(lp) && seen.insert(lp).second) todo.push_back(p);
        }
    }
    if (todo.empty()) return;
    std::atomic<size_t> idx{0};
    auto worker = [&] {
        for (;;) {
            size_t i = idx++;
            if (i >= todo.size()) break;
            int r = verifySig(todo[i]);
            std::lock_guard<std::mutex> lk(g_sigMx);
            g_sigCache[lowerW(todo[i])] = r;
        }
    };
    size_t n = std::min<size_t>(16, todo.size());
    vector<std::thread> th;
    for (size_t i = 0; i < n; i++) th.emplace_back(worker);
    for (auto& t : th) t.join();
}

static int sigOf(const wstring& p) {
    std::lock_guard<std::mutex> lk(g_sigMx);
    auto it = g_sigCache.find(lowerW(p));
    return it == g_sigCache.end() ? 2 : it->second;
}

// ============================================================ пути и анализ
static bool isPE(const wstring& e) {
    return e == L".exe" || e == L".dll" || e == L".scr" || e == L".sys" || e == L".ocx" || e == L".com" || e == L".cpl";
}
static bool isScript(const wstring& e) {
    static const set<wstring> s = {L".bat", L".cmd", L".vbs", L".vbe", L".js", L".jse", L".wsf", L".hta", L".ps1", L".jar", L".pif"};
    return s.count(e) > 0;
}
static bool isSysPath(const wstring& lp) {
    if (!startsW(lp, g_win + L"\\")) return false;
    static const wchar_t* bad[] = {L"\\temp\\", L"\\tasks\\", L"\\debug\\", L"\\tracing\\", L"\\registration\\"};
    for (auto b : bad) if (hasW(lp, b)) return false;
    return true;
}

static wstring extractExe(const wstring& cmdIn) {
    wstring c = trimW(expand(trimW(cmdIn)));
    if (c.empty()) return L"";
    if (startsW(c, L"\\??\\")) c = c.substr(4);
    wstring r;
    if (c[0] == L'"') {
        size_t e = c.find(L'"', 1);
        r = c.substr(1, e == wstring::npos ? wstring::npos : e - 1);
    } else {
        wstring lc = lowerW(c);
        size_t best = wstring::npos;
        static const wchar_t* exts[] = {L".exe", L".dll", L".scr", L".bat", L".cmd", L".com", L".vbs",
                                        L".js", L".ps1", L".hta", L".jar", L".sys", L".msi"};
        for (auto e : exts) {
            size_t el = wcslen(e), p = lc.find(e);
            while (p != wstring::npos) {
                size_t en = p + el;
                if (en == lc.size() || lc[en] == L' ' || lc[en] == L'"' || lc[en] == L',' || lc[en] == L'\t') {
                    if (best == wstring::npos || en < best) best = en;
                    break;
                }
                p = lc.find(e, p + 1);
            }
        }
        if (best != wstring::npos) r = c.substr(0, best);
        else { size_t sp = c.find(L' '); r = c.substr(0, sp); }
    }
    r = trimW(r);
    while (!r.empty() && r.back() == L',') r.pop_back();
    if (startsW(lowerW(r), L"\\systemroot\\")) r = g_winOrig + r.substr(11);
    if (r.find(L':') == wstring::npos && !startsW(r, L"\\\\")) {
        wstring t = g_winOrig + L"\\" + r;
        if (fileExists(t)) return t;
        t = g_winOrig + L"\\System32\\" + r;
        if (fileExists(t)) return t;
        return L"";
    }
    return r;
}

static bool resolveLnk(const wstring& lnk, wstring& target, wstring& args) {
    CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    bool ok = false;
    IShellLinkW* sl = nullptr;
    if (SUCCEEDED(CoCreateInstance(CLSID_ShellLink, nullptr, CLSCTX_INPROC_SERVER, IID_IShellLinkW, (void**)&sl))) {
        IPersistFile* pf = nullptr;
        if (SUCCEEDED(sl->QueryInterface(IID_IPersistFile, (void**)&pf))) {
            if (SUCCEEDED(pf->Load(lnk.c_str(), STGM_READ))) {
                wchar_t t[MAX_PATH * 2] = {0}, a[2048] = {0};
                sl->GetPath(t, MAX_PATH * 2, nullptr, SLGP_RAWPATH);
                sl->GetArguments(a, 2048);
                target = expand(t); args = a; ok = true;
            }
            pf->Release();
        }
        sl->Release();
    }
    CoUninitialize();
    return ok;
}

// ============================================================ настройки и белый список
static std::mutex g_cfgMx;
// все данные пользователя (архив, журнал, белый список, настройки) лежат в папке «Данные» рядом со сканером;
// файл из старого места при первом обращении копируется (оригинал не трогаем)
static wstring dataFile(const wchar_t* name) {
    wstring dir = g_exeDir + L"\\Данные";
    CreateDirectoryW(dir.c_str(), nullptr);
    wstring p = dir + L"\\" + name, old = g_exeDir + L"\\" + name;
    if (GetFileAttributesW(p.c_str()) == INVALID_FILE_ATTRIBUTES && GetFileAttributesW(old.c_str()) != INVALID_FILE_ATTRIBUTES)
        CopyFileW(old.c_str(), p.c_str(), TRUE);
    return p;
}
static bool g_wlOn = true, g_defOn = false, g_updOff = false;
static const char* APP_VERSION = "1.1.0";
struct WlEntry { string key, hash, date; wstring name; };
static vector<WlEntry> g_wl;

static string readFileStr(const wstring& p) {
    string s; FILE* f = _wfopen(p.c_str(), L"rb");
    if (!f) return s;
    char b[4096]; size_t n;
    while ((n = fread(b, 1, sizeof b, f)) > 0) s.append(b, n);
    fclose(f);
    return s;
}
static void writeFileStr(const wstring& p, const string& s) {
    FILE* f = _wfopen(p.c_str(), L"wb");
    if (!f) return;
    fwrite(s.data(), 1, s.size(), f);
    fclose(f);
}
static void saveSettings() {
    writeFileStr(dataFile(L"settings.json"), string("{\"whitelist\":") + (g_wlOn ? "true" : "false") +
                                                    ",\"defender\":" + (g_defOn ? "true" : "false") +
                                                    ",\"updates\":" + (g_updOff ? "false" : "true") + "}\n");
}
static void saveWl() {
    string o;
    for (auto& e : g_wl) o += e.key + "\t" + e.hash + "\t" + e.date + "\t" + u8(e.name) + "\n";
    writeFileStr(dataFile(L"whitelist.txt"), o);
}
static map<string, string> g_ack;      // ключ элемента -> время, когда отмечен прочитанным
static map<string, string> g_ackLbl;   // ключ элемента -> понятное описание (имя — путь) для файла «Архив.txt»
static void saveAcks() {
    string o;
    for (auto& e : g_ack) { auto l = g_ackLbl.find(e.first); o += e.first + "\t" + e.second + "\t" + (l == g_ackLbl.end() ? "" : l->second) + "\n"; }
    writeFileStr(dataFile(L"acks.txt"), o);
    // читаемая копия архива: новые записи сверху
    vector<std::pair<string, string>> rows;
    for (auto& e : g_ack) { auto l = g_ackLbl.find(e.first); rows.push_back({e.second, l == g_ackLbl.end() ? e.first : l->second}); }
    std::sort(rows.begin(), rows.end(), [](const std::pair<string, string>& a, const std::pair<string, string>& b) { return a.first > b.first; });
    string h = "Архив сканера — элементы, отмеченные прочитанными (" + std::to_string(rows.size()) + ")\r\n"
               "Файл только для чтения: изменения вносите в сканере (раздел «Архив»).\r\n\r\n";
    for (auto& r : rows) h += r.first + "   " + r.second + "\r\n";
    writeFileStr(dataFile(L"Архив.txt"), h);
}
static string nowStamp() {
    SYSTEMTIME t; GetLocalTime(&t);
    char d[32]; snprintf(d, 32, "%04d-%02d-%02d %02d:%02d:%02d", t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute, t.wSecond);
    return d;
}
// журнал событий: время, тип, описание (journal.log рядом с exe)
static std::mutex g_jMx;
static void jlog(const string& kind, const string& text, const string& token = "") {
    std::lock_guard<std::mutex> lk(g_jMx);
    string t = text;
    for (auto& c : t) if (c == '\t' || c == '\n' || c == '\r') c = ' ';
    string line = nowStamp() + "\t" + kind + "\t" + t + (token.empty() ? "" : "\t" + token) + "\n";
    FILE* f = _wfopen((dataFile(L"journal.log")).c_str(), L"ab");
    if (!f) return;
    fwrite(line.data(), 1, line.size(), f);
    fclose(f);
}
static string journalJson() {
    string a;
    { std::lock_guard<std::mutex> lk(g_jMx); a = readFileStr(dataFile(L"journal.log")); }
    vector<string> lines; size_t p = 0;
    while (p < a.size()) {
        size_t e = a.find('\n', p);
        string ln = a.substr(p, e == string::npos ? string::npos : e - p);
        p = e == string::npos ? a.size() : e + 1;
        if (!ln.empty()) lines.push_back(ln);
    }
    // разбор строк: время, тип, текст, [токен отмены]; отменённым считается последнее действие с таким токеном
    struct Ev { string t, k, x, u; bool done = false; };
    vector<Ev> ev; map<string, size_t> lastByTok;
    for (auto& ln : lines) {
        size_t t1 = ln.find('\t'), t2 = t1 == string::npos ? t1 : ln.find('\t', t1 + 1);
        if (t2 == string::npos) continue;
        Ev e; e.t = ln.substr(0, t1); e.k = ln.substr(t1 + 1, t2 - t1 - 1);
        size_t t3 = ln.find('\t', t2 + 1);
        e.x = ln.substr(t2 + 1, t3 == string::npos ? string::npos : t3 - t2 - 1);
        if (t3 != string::npos) e.u = ln.substr(t3 + 1);
        if (e.k == "undo") { auto f = lastByTok.find(e.u); if (f != lastByTok.end()) ev[f->second].done = true; e.u.clear(); }
        else if (!e.u.empty()) lastByTok[e.u] = ev.size();
        ev.push_back(std::move(e));
    }
    string o = "{\"events\":[";
    int n = 0;
    for (size_t i = ev.size(); i-- > 0 && n < 500; n++) {
        if (n) o += ",";
        o += "{\"t\":\"" + jesc(ev[i].t) + "\",\"k\":\"" + jesc(ev[i].k) + "\",\"x\":\"" + jesc(ev[i].x) + "\",\"u\":\"" +
             jesc(ev[i].done ? "" : ev[i].u) + "\",\"done\":" + (ev[i].done ? "true" : "false") + "}";
    }
    return o + "]}";
}
// когда элемент замечен впервые (seen.txt); у раздела первый скан — «база», новыми считаются только последующие находки
static std::mutex g_seenMx;
static map<string, string> g_seen;
static set<string> g_seenCats;
static void saveSeen() {
    string o;
    for (auto& c : g_seenCats) o += "#\t" + c + "\n";
    for (auto& e : g_seen) o += e.first + "\t" + e.second + "\n";
    writeFileStr(dataFile(L"seen.txt"), o);
}
static map<string, map<string, string>> g_snap;   // раздел -> (ключ -> описание) с прошлого анализа
static void saveSnap() {
    string o;
    for (auto& c : g_snap) for (auto& e : c.second) {
        string l = e.second;
        for (auto& ch : l) if (ch == '\t' || ch == '\n' || ch == '\r') ch = ' ';
        o += c.first + "\t" + e.first + "\t" + l + "\n";
    }
    writeFileStr(dataFile(L"snapshot.txt"), o);
}
static void loadCfg() {
    {
        string a = readFileStr(dataFile(L"snapshot.txt"));
        size_t p = 0;
        while (p < a.size()) {
            size_t e = a.find('\n', p);
            string line = a.substr(p, e == string::npos ? string::npos : e - p);
            p = e == string::npos ? a.size() : e + 1;
            size_t t1 = line.find('\t'), t2 = t1 == string::npos ? t1 : line.find('\t', t1 + 1);
            if (t2 == string::npos) continue;
            g_snap[line.substr(0, t1)][line.substr(t1 + 1, t2 - t1 - 1)] = line.substr(t2 + 1);
        }
    }
    {
        string a = readFileStr(dataFile(L"seen.txt"));
        size_t p = 0;
        while (p < a.size()) {
            size_t e = a.find('\n', p);
            string line = a.substr(p, e == string::npos ? string::npos : e - p);
            p = e == string::npos ? a.size() : e + 1;
            size_t t = line.find('\t');
            if (t == string::npos) continue;
            if (line.compare(0, t, "#") == 0) g_seenCats.insert(line.substr(t + 1));
            else g_seen[line.substr(0, t)] = line.substr(t + 1);
        }
    }
    {
        string a = readFileStr(dataFile(L"acks.txt"));
        size_t p = 0;
        while (p < a.size()) {
            size_t e = a.find('\n', p);
            string line = a.substr(p, e == string::npos ? string::npos : e - p);
            p = e == string::npos ? a.size() : e + 1;
            size_t t = line.find('\t');
            if (line.empty()) continue;
            string key = t == string::npos ? line : line.substr(0, t), rest = t == string::npos ? "" : line.substr(t + 1);
            size_t t2 = rest.find('\t');
            g_ack[key] = t2 == string::npos ? rest : rest.substr(0, t2);
            if (t2 != string::npos) g_ackLbl[key] = rest.substr(t2 + 1);
        }
    }
    string s = readFileStr(dataFile(L"settings.json"));
    if (!s.empty()) {
        g_wlOn = s.find("\"whitelist\":false") == string::npos;
        g_defOn = s.find("\"defender\":true") != string::npos;
        g_updOff = s.find("\"updates\":false") != string::npos;
    }
    string w = readFileStr(dataFile(L"whitelist.txt"));
    size_t pos = 0;
    while (pos < w.size()) {
        size_t e = w.find('\n', pos);
        string line = w.substr(pos, e == string::npos ? string::npos : e - pos);
        pos = e == string::npos ? w.size() : e + 1;
        if (line.empty()) continue;
        vector<string> f; size_t a = 0;
        for (int i = 0; i < 3; i++) {
            size_t t = line.find('\t', a);
            if (t == string::npos) break;
            f.push_back(line.substr(a, t - a)); a = t + 1;
        }
        f.push_back(line.substr(a));
        if (f.size() < 4) continue;
        g_wl.push_back({f[0], f[1], f[2], toWide(f[3])});
    }
}

static string sha256File(const wstring& p) {
    HANDLE f = CreateFileW(p.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                           OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (f == INVALID_HANDLE_VALUE) return "";
    LARGE_INTEGER sz{}; GetFileSizeEx(f, &sz);
    if (sz.QuadPart > 300LL * 1024 * 1024) { CloseHandle(f); return ""; }
    BCRYPT_ALG_HANDLE alg = nullptr; BCRYPT_HASH_HANDLE h = nullptr; string hex;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) == 0) {
        if (BCryptCreateHash(alg, &h, nullptr, 0, nullptr, 0, 0) == 0) {
            vector<BYTE> buf(1 << 20); DWORD n = 0; bool ok = true;
            while (ReadFile(f, buf.data(), (DWORD)buf.size(), &n, nullptr) && n)
                if (BCryptHashData(h, buf.data(), n, 0) != 0) { ok = false; break; }
            BYTE d[32];
            if (ok && BCryptFinishHash(h, d, 32, 0) == 0) {
                char b[3];
                for (int i = 0; i < 32; i++) { snprintf(b, 3, "%02x", d[i]); hex += b; }
            }
            BCryptDestroyHash(h);
        }
        BCryptCloseAlgorithmProvider(alg, 0);
    }
    CloseHandle(f);
    return hex;
}

// ключ белого списка: для сторонних файлов — путь (+хэш), для остального — раздел|имя|команда
static string wlKey(const WItem& it) {
    if (!it.exe.empty()) {
        wstring lp = lowerW(it.exe);
        if (!isSysPath(lp) && fileExists(it.exe)) return "p|" + u8(lp);
    }
    wstring k = toWide(it.cat) + L"|" + lowerW(it.name) + L"|" + lowerW(it.detail);
    for (auto& c : k) if (c == L'\t' || c == L'\n' || c == L'\r') c = L' ';
    return "k|" + u8(k);
}
static void applyWhitelist(vector<WItem>& v) {
    std::lock_guard<std::mutex> lk(g_cfgMx);
    if (g_wl.empty()) return;
    map<string, const WlEntry*> m;
    for (auto& e : g_wl) m[e.key] = &e;
    for (auto& it : v) {
        auto f = m.find(wlKey(it));
        if (f == m.end()) continue;
        if (f->first[0] == 'p' && !f->second->hash.empty() && sha256File(it.exe) != f->second->hash) {
            it.reasons.push_back("Файл изменился с момента добавления в белый список");
            it.risk = std::min(100, it.risk + 15);
            continue;
        }
        it.wl = true;
    }
}

static void applyAck(vector<WItem>& v) {
    std::lock_guard<std::mutex> lk(g_cfgMx);
    if (g_ack.empty()) return;
    for (auto& it : v) { auto f = g_ack.find(wlKey(it)); if (f != g_ack.end()) { it.ack = true; it.ackAt = f->second; } }
}

static string itemLabel(const WItem& it) {
    string x = u8(it.name);
    wstring w = !it.full.empty() ? it.full : !it.exe.empty() ? it.exe : it.detail;
    if (!w.empty()) x += " — " + u8(w);
    return x;
}
static const char* levelOf(int r) { return r >= 70 ? "danger" : r >= 35 ? "warn" : r >= 15 ? "note" : "ok"; }

struct Pat { const wchar_t* s; int p; const char* why; };
static const Pat PATS[] = {
    {L" -enc ", 40, "PowerShell с закодированной командой"},
    {L"-encodedcommand", 40, "PowerShell с закодированной командой"},
    {L"-windowstyle hidden", 25, "Запуск в скрытом окне"},
    {L"-w hidden", 25, "Запуск в скрытом окне"},
    {L"mshta", 30, "Использует mshta (запуск HTA-скриптов)"},
    {L"wscript", 20, "Запускает скрипт через Windows Script Host"},
    {L"cscript", 20, "Запускает скрипт через Windows Script Host"},
    {L"scrobj.dll", 40, "Подозрительный вызов regsvr32/scrobj"},
    {L"javascript:", 40, "Встроенный JavaScript в команде"},
    {L"vbscript:", 40, "Встроенный VBScript в команде"},
    {L"http://", 20, "Команда обращается к адресу в сети"},
    {L"https://", 20, "Команда обращается к адресу в сети"},
    {L"frombase64string", 40, "Декодирование base64 в команде"},
    {L"invoke-expression", 35, "Выполнение строки как кода (Invoke-Expression)"},
    {L" iex ", 35, "Выполнение строки как кода (iex)"},
    {L"downloadstring", 40, "Скачивание и запуск кода из сети"},
    {L"downloadfile", 35, "Скачивание файла из сети"},
    {L"bitsadmin", 25, "Использует bitsadmin для загрузки"},
    {L"-urlcache", 40, "certutil скачивает файл из сети"},
};

static void analyzeItem(WItem& it) {
    auto add = [&](int p, const string& r) { it.risk += p; it.reasons.push_back(r); };
    const string& cat = it.cat;
    bool isRun = cat.rfind("run", 0) == 0, isStartup = cat.rfind("startup", 0) == 0;
    bool isAuto = isRun || isStartup || cat == "tasks" || cat == "services" || cat == "policies_run" ||
                  cat == "ifeo" || cat == "appinit" || cat == "activesetup";
    wstring lname = lowerW(it.name), lcmd = lowerW(it.detail);

    // --- Winlogon: сравниваем с эталоном
    if (cat == "winlogon") {
        wstring v = lowerW(trimW(it.detail));
        if (lname == L"shell") {
            if (v != L"explorer.exe") add(90, "Оболочка Windows подменена (ожидается explorer.exe)");
        } else if (lname == L"userinit") {
            while (!v.empty() && v.back() == L',') v.pop_back();
            if (v != g_win + L"\\system32\\userinit.exe") add(90, "Userinit подменён или дополнен");
        } else if (lname == L"vmapplet") {
            if (v != L"systempropertiesperformance.exe /pagefile") add(60, "Нестандартное значение VMApplet");
        } else if (!v.empty()) {
            add(60, "Необычный параметр Winlogon — обычно его нет");
        }
        it.risk = std::min(100, it.risk);
        return;
    }

    // --- файл hosts: подмена адресов
    if (cat == "hosts") {
        static const wchar_t* av[] = {L"windowsupdate", L"microsoft", L"defender", L"kaspersky", L"eset", L"avast", L"avg.",
                                      L"avira", L"malwarebytes", L"bitdefender", L"norton", L"mcafee", L"virustotal",
                                      L"drweb", L"sophos", L"symantec", L"trendmicro", L"comodo"};
        static const wchar_t* pop[] = {L"google", L"steam", L"epicgames", L"discord", L"roblox", L"adobe", L"nvidia",
                                       L"github", L"facebook", L"youtube", L"vk.com", L"yandex"};
        bool hit = false;
        for (auto a : av) if (hasW(lname, a)) { add(70, "Запись блокирует или подменяет адрес антивируса/обновлений Windows"); hit = true; break; }
        if (!hit) for (auto a : pop) if (hasW(lname, a)) { add(40, "Запись подменяет адрес популярного сервиса"); hit = true; break; }
        if (!hit) add(20, "Нестандартная запись в hosts");
        return;
    }
    if (cat == "ifeo") add(45, "Перехват запуска программы через IFEO (Debugger) — приём закрепления вирусов");
    if (cat == "appinit") add(50, "AppInit_DLLs: библиотека подгружается в каждое приложение");
    if (cat == "network") {
        static const set<wstring> ports = {L"4444", L"5555", L"1337", L"31337", L"6667", L"12345"};
        if (it.state == L"estab" && ports.count(it.start)) add(30, "Подключение к порту, типичному для удалённого управления");
    }
    if (cat == "defender") { it.risk = std::min(100, it.risk); return; }  // риск задан сборщиком

    wstring lpath = lowerW(it.exe), ext = extOf(it.exe);
    bool exec = isPE(ext) || isScript(ext) || (isAuto && !it.exe.empty());
    bool sys = !lpath.empty() && isSysPath(lpath);
    bool exists = !it.exe.empty() && fileExists(it.exe);
    if (cat == "tasks" && startsW(lname, L"\\microsoft\\") && (it.exe.empty() || sys)) it.sig = "system";

    // --- имитация системных процессов
    if (cat == "processes" && !lpath.empty()) {
        static const set<wstring> mimic = {L"svchost.exe", L"lsass.exe", L"csrss.exe", L"services.exe",
                                           L"winlogon.exe", L"smss.exe", L"wininit.exe", L"explorer.exe",
                                           L"taskhostw.exe", L"dwm.exe", L"spoolsv.exe"};
        if (mimic.count(lname) && !startsW(lpath, g_win + L"\\system32\\") && !startsW(lpath, g_win + L"\\syswow64\\") &&
            lpath != g_win + L"\\explorer.exe")
            add(90, "Имитирует системный процесс, но запущен не из системной папки");
    }

    if (it.exe.empty()) { it.risk = std::min(100, it.risk); return; }

    // --- битая запись
    if (!exists) {
        it.sig = "missing";
        if (isAuto) add(20, "Файл не найден — «висячая» запись автозапуска");
    } else if (sys) {
        it.sig = "system";
    } else if (isPE(ext)) {
        int s = sigOf(it.exe);
        it.sig = s == 1 ? "signed" : s == 0 ? "unsigned" : s == 3 ? "invalid" : "unverified";
        if (s == 0) add(25, "Нет цифровой подписи");
        else if (s == 3) add(50, "Цифровая подпись нарушена — файл изменён");
        else if (s == 2) add(5, "Подпись не удалось проверить");
    }

    if (exec && !sys && exists) {
        struct Loc { const wchar_t* s; int p; const char* why; };
        static const Loc locs[] = {
            {L"\\appdata\\local\\temp\\", 35, "Расположен во временной папке"},
            {L"\\windows\\temp\\", 35, "Расположен во временной папке Windows"},
            {L"\\$recycle.bin\\", 40, "Расположен в корзине"},
            {L"\\users\\public\\", 30, "Расположен в общей папке Public"},
            {L"\\downloads\\", 12, "Лежит в папке «Загрузки»"},
            {L"\\appdata\\roaming\\", 15, "Расположен в AppData\\Roaming"},
            {L"\\programdata\\", 15, "Расположен в ProgramData"},
        };
        bool placed = false;
        for (auto& l : locs) if (hasW(lpath, l.s)) { add(l.p, l.why); placed = true; break; }
        if (!placed && hasW(lpath, L"\\appdata\\local\\") && !hasW(lpath, L"\\appdata\\local\\programs\\") &&
            !hasW(lpath, L"\\appdata\\local\\microsoft\\"))
            add(8, "Расположен в AppData\\Local");
        if (isScript(ext)) add(isAuto ? 20 : 10, "Скриптовый файл");
        if (it.hidden) add(15, "Скрытый файл");
    }

    // --- двойное расширение, «случайное» имя
    if (exec) {
        wstring b = lowerW(baseName(it.exe));
        static const wchar_t* fake[] = {L".pdf.", L".doc.", L".docx.", L".jpg.", L".png.", L".txt.", L".xls.", L".xlsx.", L".mp3.", L".mp4."};
        for (auto f : fake) if (b.find(f) != wstring::npos && (isPE(ext) || isScript(ext))) { add(50, "Двойное расширение — маскировка под документ"); break; }
        size_t dot = b.rfind(L'.');
        wstring stem = dot == wstring::npos ? b : b.substr(0, dot);
        if (stem.size() >= 12) {
            bool alnum = true; int vow = 0;
            for (wchar_t ch : stem) {
                if (!((ch >= L'a' && ch <= L'z') || (ch >= L'0' && ch <= L'9'))) { alnum = false; break; }
                if (wcschr(L"aeiouy", ch)) vow++;
            }
            if (alnum && vow * 5 < (int)stem.size()) add(15, "Имя файла выглядит случайным");
        }
    }

    // --- подозрительные команды
    if (isAuto && !lcmd.empty()) {
        set<string> done; int pts = 0;
        for (auto& p : PATS) {
            if (lcmd.find(p.s) != wstring::npos && done.insert(p.why).second) {
                pts += p.p; it.reasons.push_back(p.why);
            }
        }
        it.risk += std::min(pts, 80);
        if (sys || lpath.empty()) {
            // системная программа (cmd/powershell/...) запускает что-то из пользовательской папки
            static const wchar_t* ul[] = {L"\\appdata\\", L"\\temp\\", L"\\programdata\\", L"\\users\\public\\", L"\\downloads\\"};
            for (auto u : ul) if (hasW(lcmd, u)) { add(30, "Системная утилита запускает файл из пользовательской папки"); break; }
        }
    }

    if (it.sig == "signed" && it.risk > 0) it.risk = std::max(0, it.risk - 15);
    // библиотеки сами по себе не запускаются: без явных признаков подмены не выше «Подозрительно»
    if (ext == L".dll" && it.sig != "invalid" && cat != "processes") it.risk = std::min(it.risk, 55);
    it.risk = std::max(0, std::min(100, it.risk));
}

static void finishCat(vector<WItem>& v, const string& cat, vector<string>* goneOut = nullptr) {
    vector<wstring> need;
    for (auto& it : v) {
        it.cat = cat;
        if (it.exe.empty() || !isPE(extOf(it.exe))) continue;
        wstring lp = lowerW(it.exe);
        if (isSysPath(lp)) continue;
        if (fileExists(it.exe)) need.push_back(it.exe);
    }
    sigBatch(need);
    for (auto& it : v) analyzeItem(it);
    applyWhitelist(v);
    applyAck(v);
    if (cat != "processes" && cat != "network" && cat != "custom") {
        vector<string> fresh, gone;
        {
            std::lock_guard<std::mutex> lk(g_seenMx);
            bool base = g_seenCats.count(cat) > 0, changed = !base;
            string now = nowStamp();
            for (auto& it : v) {
                string k = cat + "@" + wlKey(it);
                auto f = g_seen.find(k);
                if (f == g_seen.end()) {
                    g_seen[k] = now; it.first = now; changed = true;
                    if (base) { it.isnew = true; if (!it.wl && !it.ack && it.risk >= 35) fresh.push_back(itemLabel(it)); }
                } else it.first = f->second;
            }
            g_seenCats.insert(cat);
            if (changed) saveSeen();
            // что пропало с прошлого анализа: сравниваем со снимком этого раздела (шумные разделы не сравниваем)
            static const set<string> noisy = {"files", "temp", "roaming", "programdata"};
            if (!noisy.count(cat)) {
                map<string, string> cur;
                for (auto& it : v) cur[cat + "@" + wlKey(it)] = itemLabel(it);
                auto prev = g_snap.find(cat);
                if (prev != g_snap.end())
                    for (auto& kv : prev->second)
                        if (!cur.count(kv.first)) gone.push_back(kv.second);
                if (cur.size() <= 4000) g_snap[cat] = std::move(cur);
                saveSnap();
            }
        }
        for (auto& x : fresh) jlog("found", "Новая находка: " + x);
        for (size_t i = 0; i < gone.size() && i < 30; i++) jlog("gone", "Пропало: " + gone[i]);
        if (goneOut) *goneOut = gone;
    }
}

// ============================================================ сборщики
static void listDir(vector<WItem>& out, const wstring& dir, size_t cap, bool lnk, bool* trunc) {
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileExW((dir + L"\\*").c_str(), FindExInfoBasic, &fd, FindExSearchNameMatch, nullptr, FIND_FIRST_EX_LARGE_FETCH);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        wstring nm = fd.cFileName;
        if (nm == L"." || nm == L"..") continue;
        if (_wcsicmp(nm.c_str(), L"desktop.ini") == 0 || _wcsicmp(nm.c_str(), L"thumbs.db") == 0) continue;
        if (out.size() >= cap) { if (trunc) *trunc = true; break; }
        WItem it;
        it.name = nm; it.detail = dir; it.full = dir + L"\\" + nm;
        it.isDir = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
        it.hidden = (fd.dwFileAttributes & FILE_ATTRIBUTE_HIDDEN) != 0;
        if (!it.isDir) it.size = ((long long)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
        it.mtime = fmtTime(fd.ftLastWriteTime);
        bool reparse = (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
        if (!it.isDir) it.exe = it.full;
        if (lnk && !it.isDir && extOf(nm) == L".lnk") {
            wstring t, a;
            if (resolveLnk(it.full, t, a)) { it.exe = t; it.detail = trimW(t + L" " + a); }
            else it.exe.clear();
        }
        { // обычные данные (ini, txt…) не анализируем как программы
            wstring e = extOf(nm);
            if (!it.isDir && !isPE(e) && !isScript(e) && !(lnk && e == L".lnk")) it.exe.clear();
        }
        if (!reparse && nm != L"desktop.ini") {
            it.action = "quarantine";
            it.del.kind = it.isDir ? Kind::Dir : Kind::File;
            it.del.display = nm; it.del.path = it.full;
        }
        out.push_back(std::move(it));
    } while (FindNextFileW(h, &fd));
    FindClose(h);
}

static void colReg(vector<WItem>& out, HKEY root, const wstring& path, REGSAM view, bool winlogon = false) {
    HKEY k;
    if (RegOpenKeyExW(root, path.c_str(), 0, KEY_READ | view, &k) != ERROR_SUCCESS) return;
    vector<wchar_t> name(16384);
    vector<BYTE> data(65536);
    static const set<wstring> watched = {L"shell", L"userinit", L"taskman", L"appsetup", L"vmapplet", L"ginadll", L"uihost", L"system"};
    for (DWORD i = 0;; i++) {
        DWORD nl = 16383, dl = (DWORD)data.size() - 4, type = 0;
        LONG r = RegEnumValueW(k, i, name.data(), &nl, nullptr, &type, data.data(), &dl);
        if (r == ERROR_NO_MORE_ITEMS) break;
        if (r != ERROR_SUCCESS) continue;
        data[dl] = data[dl + 1] = 0;
        wstring nm(name.data(), nl), val;
        if (winlogon && !watched.count(lowerW(nm))) continue;
        if (type == REG_SZ || type == REG_EXPAND_SZ) val = (wchar_t*)data.data();
        else if (type == REG_DWORD && dl >= 4) val = std::to_wstring(*(DWORD*)data.data());
        else if (type == REG_MULTI_SZ) {
            wchar_t* p = (wchar_t*)data.data();
            while (*p) { if (!val.empty()) val += L"; "; val += p; p += wcslen(p) + 1; }
        } else val = L"(бинарные данные)";
        WItem it;
        it.name = nm; it.detail = val;
        if (!winlogon) it.exe = extractExe(val);
        it.full = it.exe;
        if (!winlogon) {
            it.action = "regdel";
            it.del.kind = Kind::RegValue; it.del.display = nm; it.del.path = path;
            it.del.extra = nm; it.del.root = root; it.del.view = view;
        }
        out.push_back(std::move(it));
    }
    RegCloseKey(k);
}

static void colServices(vector<WItem>& out) {
    SC_HANDLE sc = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
    if (!sc) return;
    DWORD need = 0, cnt = 0, resume = 0;
    EnumServicesStatusExW(sc, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, nullptr, 0, &need, &cnt, &resume, nullptr);
    string buf(need + 4096, 0);
    resume = 0;
    if (EnumServicesStatusExW(sc, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, (LPBYTE)buf.data(),
                              (DWORD)buf.size(), &need, &cnt, &resume, nullptr)) {
        auto* s = (ENUM_SERVICE_STATUS_PROCESSW*)buf.data();
        for (DWORD i = 0; i < cnt; i++) {
            WItem it;
            it.name = s[i].lpServiceName;
            it.sub = s[i].lpDisplayName ? s[i].lpDisplayName : L"";
            it.state = s[i].ServiceStatusProcess.dwCurrentState == SERVICE_RUNNING ? L"running" : L"stopped";
            it.start = L"?";
            SC_HANDLE h = OpenServiceW(sc, s[i].lpServiceName, SERVICE_QUERY_CONFIG);
            if (h) {
                DWORD n = 0;
                QueryServiceConfigW(h, nullptr, 0, &n);
                string cb(n, 0);
                if (n && QueryServiceConfigW(h, (LPQUERY_SERVICE_CONFIGW)cb.data(), n, &n)) {
                    auto* c = (LPQUERY_SERVICE_CONFIGW)cb.data();
                    it.detail = c->lpBinaryPathName ? c->lpBinaryPathName : L"";
                    switch (c->dwStartType) {
                        case SERVICE_AUTO_START: it.start = L"auto"; break;
                        case SERVICE_DEMAND_START: it.start = L"manual"; break;
                        case SERVICE_DISABLED: it.start = L"disabled"; break;
                        case SERVICE_BOOT_START: it.start = L"boot"; break;
                        case SERVICE_SYSTEM_START: it.start = L"system"; break;
                    }
                }
                CloseServiceHandle(h);
            }
            it.exe = extractExe(it.detail);
            it.full = it.exe;
            it.action = "svcdel";
            it.del.kind = Kind::Service; it.del.display = it.name; it.del.path = it.name;
            out.push_back(std::move(it));
        }
    }
    CloseServiceHandle(sc);
}

static vector<string> parseCsv(const string& s) {
    vector<string> f; string cur; bool q = false;
    for (size_t i = 0; i < s.size(); i++) {
        char c = s[i];
        if (q) {
            if (c == '"') { if (i + 1 < s.size() && s[i + 1] == '"') { cur += '"'; i++; } else q = false; }
            else cur += c;
        } else if (c == '"') q = true;
        else if (c == ',') { f.push_back(cur); cur.clear(); }
        else if (c != '\r' && c != '\n') cur += c;
    }
    f.push_back(cur);
    return f;
}

static void colTasks(vector<WItem>& out) {
    FILE* f = _popen("cmd /c \"chcp 65001 >nul & schtasks /query /fo csv /v /nh\"", "r");
    if (!f) return;
    char buf[8192];
    string acc;
    set<string> seen;
    auto flush = [&] {
        auto fl = parseCsv(acc);
        acc.clear();
        if (fl.size() < 9) return;
        string nm = fl[1];
        if (nm.empty() || nm == "TaskName" || !seen.insert(nm).second) return;
        WItem it;
        it.name = toWide(nm);
        string cmd = fl[8];
        if (cmd == "N/A" || cmd == "Н/Д") cmd.clear();
        it.detail = toWide(cmd);
        it.exe = extractExe(it.detail);
        it.full = it.exe;
        string st = fl.size() > 11 ? fl[11] : "", status = fl[3];
        bool dis = st.find("Disabled") != string::npos || st.find("Отключ") != string::npos ||
                   status.find("Disabled") != string::npos || status.find("Отключ") != string::npos;
        it.state = dis ? L"disabled" : L"enabled";
        if (fl.size() > 14) it.sub = toWide(fl[14]);
        it.action = "taskdel";
        it.del.kind = Kind::Task; it.del.display = it.name; it.del.path = it.name;
        out.push_back(std::move(it));
    };
    while (fgets(buf, sizeof(buf), f)) {
        acc += buf;
        if (acc.empty() || acc.back() != '\n') continue;
        if (std::count(acc.begin(), acc.end(), '"') % 2) continue;
        flush();
    }
    if (!acc.empty()) flush();
    _pclose(f);
}

static void colProcesses(vector<WItem>& out) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return;
    PROCESSENTRY32W pe{}; pe.dwSize = sizeof(pe);
    map<DWORD, wstring> names;
    vector<PROCESSENTRY32W> all;
    if (Process32FirstW(snap, &pe)) do { names[pe.th32ProcessID] = pe.szExeFile; all.push_back(pe); } while (Process32NextW(snap, &pe));
    CloseHandle(snap);
    for (auto& p : all) {
        WItem it;
        it.name = p.szExeFile; it.pid = p.th32ProcessID; it.ppid = p.th32ParentProcessID;
        auto pn = names.find(it.ppid);
        if (pn != names.end()) it.parent = pn->second;
        HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, p.th32ProcessID);
        if (h) {
            wchar_t b[MAX_PATH * 2]; DWORD n = MAX_PATH * 2;
            if (QueryFullProcessImageNameW(h, 0, b, &n)) it.exe = b;
            CloseHandle(h);
        }
        it.detail = it.exe; it.full = it.exe;
        it.action = "kill";
        it.del.kind = Kind::Process; it.del.display = it.name; it.del.pid = it.pid;
        out.push_back(std::move(it));
    }
}

// читает строковое значение; пустая строка, если нет
static bool regStr(HKEY k, const wchar_t* name, wstring& out) {
    wchar_t b[4096]; DWORD n = sizeof(b) - 2, type = 0;
    if (RegQueryValueExW(k, name, nullptr, &type, (BYTE*)b, &n) != ERROR_SUCCESS) return false;
    if (type != REG_SZ && type != REG_EXPAND_SZ) return false;
    b[n / 2] = 0; out = b;
    return !trimW(out).empty();
}
static void addRegDel(WItem& it, HKEY root, const wstring& path, const wstring& value, REGSAM view = 0) {
    it.action = "regdel";
    it.del.kind = Kind::RegValue; it.del.display = it.name; it.del.path = path;
    it.del.extra = value; it.del.root = root; it.del.view = view;
}

static void colIfeo(vector<WItem>& out) {
    const wstring base = L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options";
    HKEY k;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, base.c_str(), 0, KEY_READ, &k) != ERROR_SUCCESS) return;
    wchar_t nm[512];
    for (DWORD i = 0;; i++) {
        DWORD nl = 512;
        if (RegEnumKeyExW(k, i, nm, &nl, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) break;
        HKEY sk; wstring path = base + L"\\" + nm, dbg;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, path.c_str(), 0, KEY_READ, &sk) != ERROR_SUCCESS) continue;
        if (regStr(sk, L"Debugger", dbg)) {
            WItem it; it.name = nm; it.detail = dbg; it.exe = extractExe(dbg); it.full = it.exe;
            addRegDel(it, HKEY_LOCAL_MACHINE, path, L"Debugger");
            out.push_back(std::move(it));
        }
        RegCloseKey(sk);
    }
    RegCloseKey(k);
}

static void colAppInit(vector<WItem>& out) {
    const wstring path = L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows";
    for (int w = 0; w < 2; w++) {
        REGSAM view = w ? KEY_WOW64_32KEY : KEY_WOW64_64KEY;
        HKEY k; wstring v;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, path.c_str(), 0, KEY_READ | view, &k) != ERROR_SUCCESS) continue;
        if (regStr(k, L"AppInit_DLLs", v)) {
            WItem it; it.name = w ? L"AppInit_DLLs (32-бит)" : L"AppInit_DLLs"; it.detail = v;
            it.exe = extractExe(v); it.full = it.exe;
            addRegDel(it, HKEY_LOCAL_MACHINE, path, L"AppInit_DLLs", view);
            out.push_back(std::move(it));
        }
        RegCloseKey(k);
    }
}

static void colActiveSetup(vector<WItem>& out) {
    const wstring base = L"SOFTWARE\\Microsoft\\Active Setup\\Installed Components";
    HKEY k;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, base.c_str(), 0, KEY_READ, &k) != ERROR_SUCCESS) return;
    wchar_t nm[512];
    for (DWORD i = 0;; i++) {
        DWORD nl = 512;
        if (RegEnumKeyExW(k, i, nm, &nl, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) break;
        HKEY sk; wstring path = base + L"\\" + nm, stub, title;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, path.c_str(), 0, KEY_READ, &sk) != ERROR_SUCCESS) continue;
        if (regStr(sk, L"StubPath", stub)) {
            regStr(sk, L"", title);
            WItem it; it.name = title.empty() ? wstring(nm) : title; it.sub = nm; it.detail = stub;
            it.exe = extractExe(stub); it.full = it.exe;
            addRegDel(it, HKEY_LOCAL_MACHINE, path, L"StubPath");
            out.push_back(std::move(it));
        }
        RegCloseKey(sk);
    }
    RegCloseKey(k);
}

static void colHosts(vector<WItem>& out) {
    wstring path = g_winOrig + L"\\System32\\drivers\\etc\\hosts";
    string s = readFileStr(path);
    size_t pos = 0;
    while (pos < s.size()) {
        size_t e = s.find('\n', pos);
        string line = s.substr(pos, e == string::npos ? string::npos : e - pos);
        pos = e == string::npos ? s.size() : e + 1;
        size_t h = line.find('#');
        if (h != string::npos) line.resize(h);
        wstring w = trimW(toWide(line));
        if (w.empty()) continue;
        vector<wstring> tok; wstring cur;
        for (wchar_t c : w + L" ") { if (c == L' ' || c == L'\t' || c == L'\r') { if (!cur.empty()) tok.push_back(cur); cur.clear(); } else cur += c; }
        if (tok.size() < 2) continue;
        bool onlyLocal = (tok[0] == L"127.0.0.1" || tok[0] == L"::1");
        wstring names;
        for (size_t i = 1; i < tok.size(); i++) {
            if (lowerW(tok[i]) != L"localhost") onlyLocal = false;
            names += (names.empty() ? L"" : L" ") + tok[i];
        }
        if (onlyLocal) continue;
        WItem it; it.name = names; it.sub = tok[0]; it.detail = w; it.full = path;
        out.push_back(std::move(it));
    }
}

static void colNetwork(vector<WItem>& out) {
    ULONG sz = 0;
    GetExtendedTcpTable(nullptr, &sz, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    vector<BYTE> buf(sz + 8192);
    sz = (ULONG)buf.size();
    if (GetExtendedTcpTable(buf.data(), &sz, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR) return;
    auto* t = (PMIB_TCPTABLE_OWNER_PID)buf.data();
    map<DWORD, std::pair<wstring, wstring>> proc;   // pid -> (имя, путь)
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    map<DWORD, wstring> names;
    if (snap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe{}; pe.dwSize = sizeof(pe);
        if (Process32FirstW(snap, &pe)) do { names[pe.th32ProcessID] = pe.szExeFile; } while (Process32NextW(snap, &pe));
        CloseHandle(snap);
    }
    auto ip = [](DWORD a) { char b[32]; in_addr ad; ad.S_un.S_addr = a; inet_ntop(AF_INET, &ad, b, sizeof b); return string(b); };
    for (DWORD i = 0; i < t->dwNumEntries; i++) {
        auto& r = t->table[i];
        if (r.dwState != MIB_TCP_STATE_ESTAB && r.dwState != MIB_TCP_STATE_LISTEN) continue;
        bool listen = r.dwState == MIB_TCP_STATE_LISTEN;
        string lip = ip(r.dwLocalAddr), rip = ip(r.dwRemoteAddr);
        if (lip.rfind("127.", 0) == 0 && listen) continue;
        if (!listen && rip.rfind("127.", 0) == 0) continue;
        unsigned lp = ntohs((u_short)r.dwLocalPort), rp = ntohs((u_short)r.dwRemotePort);
        DWORD pid = r.dwOwningPid;
        auto pf = proc.find(pid);
        if (pf == proc.end()) {
            wstring path;
            HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
            if (h) { wchar_t b[MAX_PATH * 2]; DWORD n = MAX_PATH * 2; if (QueryFullProcessImageNameW(h, 0, b, &n)) path = b; CloseHandle(h); }
            wstring nm = names.count(pid) ? names[pid] : (pid == 4 ? L"System" : L"PID " + std::to_wstring(pid));
            pf = proc.emplace(pid, std::make_pair(nm, path)).first;
        }
        WItem it;
        it.name = pf->second.first; it.exe = pf->second.second; it.full = it.exe; it.pid = pid;
        it.state = listen ? L"listen" : L"estab";
        it.start = std::to_wstring(rp);
        it.sub = listen ? L"слушает порт " + std::to_wstring(lp) : toWide(rip) + L":" + std::to_wstring(rp);
        it.detail = toWide(lip) + L":" + std::to_wstring(lp) + (listen ? L"" : L" → " + toWide(rip) + L":" + std::to_wstring(rp));
        if (pid > 4) {
            it.action = "kill";
            it.del.kind = Kind::Process; it.del.display = it.name; it.del.pid = pid;
        }
        out.push_back(std::move(it));
    }
}

// ---------- Windows Defender (только если включено в настройках) ----------
static string b64(const string& in) {
    static const char* T = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    string o; size_t i = 0;
    for (; i + 2 < in.size(); i += 3) {
        unsigned v = ((unsigned char)in[i] << 16) | ((unsigned char)in[i + 1] << 8) | (unsigned char)in[i + 2];
        o += T[v >> 18]; o += T[(v >> 12) & 63]; o += T[(v >> 6) & 63]; o += T[v & 63];
    }
    if (i + 1 == in.size()) { unsigned v = (unsigned char)in[i] << 16; o += T[v >> 18]; o += T[(v >> 12) & 63]; o += "=="; }
    else if (i + 2 == in.size()) { unsigned v = ((unsigned char)in[i] << 16) | ((unsigned char)in[i + 1] << 8); o += T[v >> 18]; o += T[(v >> 12) & 63]; o += T[(v >> 6) & 63]; o += '='; }
    return o;
}
static string runPs(const wstring& script) {
    string raw((const char*)script.data(), script.size() * 2);
    string cmd = "powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand " + b64(raw);
    FILE* f = _popen(cmd.c_str(), "r");
    string o;
    if (!f) return o;
    char b[4096]; size_t n;
    while ((n = fread(b, 1, sizeof b, f)) > 0) o.append(b, n);
    _pclose(f);
    return o;
}
static vector<wstring> splitBar(const wstring& s) {
    vector<wstring> f; wstring cur;
    for (wchar_t c : s) { if (c == L'|') { f.push_back(cur); cur.clear(); } else cur += c; }
    f.push_back(cur);
    return f;
}
static void colDefender(vector<WItem>& out) {
    const wstring script =
        L"[Console]::OutputEncoding=[Text.Encoding]::UTF8;$ErrorActionPreference='SilentlyContinue';"
        L"$s=Get-MpComputerStatus;if($s){'S|'+$s.AntivirusEnabled+'|'+$s.RealTimeProtectionEnabled+'|'+$s.AntivirusSignatureLastUpdated.ToString('yyyy-MM-dd HH:mm')+'|'+$s.IsTamperProtected}else{'E|status'};"
        L"$p=Get-MpPreference;if($p){foreach($x in $p.ExclusionPath){if($x){'XP|'+$x}};foreach($x in $p.ExclusionExtension){if($x){'XE|'+$x}};foreach($x in $p.ExclusionProcess){if($x){'XR|'+$x}}};"
        L"$t=@{};Get-MpThreat|%{$t[[string]$_.ThreatID]=$_.ThreatName};"
        L"Get-MpThreatDetection|%{'T|'+$_.InitialDetectionTime.ToString('yyyy-MM-dd HH:mm')+'|'+$t[[string]$_.ThreatID]+'|'+(($_.Resources|%{[string]$_}) -join ';')}";
    string o = runPs(script);
    size_t pos = 0;
    bool any = false, hiddenShown = false;
    map<wstring, size_t> thrIdx; map<wstring, int> thrCnt; map<wstring, wstring> thrFirst;   // одна угроза в одном месте = одна строка
    while (pos < o.size()) {
        size_t e = o.find('\n', pos);
        string ln = o.substr(pos, e == string::npos ? string::npos : e - pos);
        pos = e == string::npos ? o.size() : e + 1;
        while (!ln.empty() && (ln.back() == '\r' || ln.back() == ' ')) ln.pop_back();
        if (ln.empty()) continue;
        auto f = splitBar(toWide(ln));
        if (f.empty()) continue;
        WItem it;
        if (f[0] == L"S" && f.size() >= 5) {
            any = true;
            bool av = f[1] == L"True", rtp = f[2] == L"True", tamper = f[4] == L"True";
            it.name = L"Состояние Защитника Windows";
            it.detail = wstring(L"Антивирус: ") + (av ? L"включён" : L"выключен") + L" · защита в реальном времени: " +
                        (rtp ? L"включена" : L"выключена") + L" · базы обновлены: " + f[3] + L" · защита от подделки: " + (tamper ? L"включена" : L"выключена");
            if (!av) { it.risk = 40; it.reasons.push_back("Антивирус Защитника выключен (возможно, установлен другой антивирус)"); }
            if (av && !rtp) { it.risk = 50; it.reasons.push_back("Защита в реальном времени отключена"); }
        } else if (f[0] == L"XP" || f[0] == L"XE" || f[0] == L"XR") {
            any = true;
            wstring v = f.size() > 1 ? f[1] : L"";
            if (startsW(v, L"N/A")) {
                if (hiddenShown) continue;
                hiddenShown = true;
                it.name = L"Исключения скрыты"; it.detail = L"Чтобы увидеть исключения Защитника, запусти сканер от администратора";
            } else {
                const wchar_t* kind = f[0] == L"XP" ? L"Исключение: путь" : f[0] == L"XE" ? L"Исключение: расширение" : L"Исключение: процесс";
                it.name = v; it.sub = kind; it.detail = kind;
                it.risk = f[0] == L"XE" ? 25 : 40;
                it.reasons.push_back("Добавлено в исключения Защитника — вредоносные программы часто прячутся именно так");
                if (f[0] == L"XP" && fileExists(v)) it.full = v;
            }
        } else if (f[0] == L"T" && f.size() >= 4) {
            any = true;
            it.name = f[2].empty() ? L"Обнаруженная угроза" : f[2];
            it.detail = f[3]; it.mtime = f[1];
            it.risk = 90;
            wstring tk = it.name + L"|" + it.detail;
            auto ex = thrIdx.find(tk);
            if (ex != thrIdx.end()) {
                WItem& w = out[ex->second];
                thrCnt[tk]++;
                if (f[1] > w.mtime) w.mtime = f[1];
                if (f[1] < thrFirst[tk]) thrFirst[tk] = f[1];
                continue;
            }
            thrIdx[tk] = out.size(); thrCnt[tk] = 1; thrFirst[tk] = f[1];
            it.reasons.push_back("Защитник Windows обнаружил угрозу");
        } else continue;
        out.push_back(std::move(it));
    }
    for (auto& kv : thrIdx) {
        WItem& w = out[kv.second];
        int n = thrCnt[kv.first];
        if (n > 1) {
            w.sub = L"обнаружено " + std::to_wstring(n) + L" раз";
            w.reasons.push_back("Первое обнаружение: " + u8(thrFirst[kv.first]) + ", последнее: " + u8(w.mtime));
        } else w.reasons.push_back("Обнаружено: " + u8(w.mtime));
    }
    if (!any) {
        WItem it; it.name = L"Нет данных от Защитника"; it.detail = L"Защитник Windows недоступен или отключён политикой";
        out.push_back(std::move(it));
    }
}

static void walk(const wstring& dir, int depth, int maxDepth, bool dll, vector<WItem>& out, size_t cap,
                 const set<wstring>& skip, set<wstring>& seen, size_t& visited) {
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileExW((dir + L"\\*").c_str(), FindExInfoBasic, &fd, FindExSearchNameMatch, nullptr, FIND_FIRST_EX_LARGE_FETCH);
    if (h == INVALID_HANDLE_VALUE) return;
    vector<wstring> subs;
    do {
        wstring nm = fd.cFileName;
        if (nm == L"." || nm == L"..") continue;
        if (++visited > 250000 || out.size() >= cap) break;
        bool isDir = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
        if (isDir) {
            if ((fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) || depth >= maxDepth) continue;
            if (skip.count(lowerW(nm))) continue;
            subs.push_back(dir + L"\\" + nm);
            continue;
        }
        wstring e = extOf(nm);
        bool want = (isPE(e) && e != L".sys" && e != L".ocx" && e != L".cpl" && (e != L".dll" || dll)) || isScript(e);
        if (!want) continue;
        wstring full = dir + L"\\" + nm;
        if (!seen.insert(lowerW(full)).second) continue;
        WItem it;
        it.name = nm; it.detail = dir; it.full = full; it.exe = full;
        it.size = ((long long)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
        it.mtime = fmtTime(fd.ftLastWriteTime);
        it.hidden = (fd.dwFileAttributes & FILE_ATTRIBUTE_HIDDEN) != 0;
        it.action = "quarantine";
        it.del.kind = Kind::File; it.del.display = nm; it.del.path = full;
        out.push_back(std::move(it));
    } while (FindNextFileW(h, &fd));
    FindClose(h);
    for (auto& s : subs) {
        if (out.size() >= cap || visited > 250000) break;
        walk(s, depth + 1, maxDepth, dll, out, cap, skip, seen, visited);
    }
}

static void colDeepFiles(vector<WItem>& out, bool* trunc) {
    const size_t cap = 4000;
    set<wstring> seen;
    size_t visited = 0;
    wstring local = expand(L"%LOCALAPPDATA%"), prof = expand(L"%USERPROFILE%");
    struct Root { wstring path; int depth; bool dll; set<wstring> skip; };
    vector<Root> roots = {
        {local + L"\\Temp", 3, true, {}},
        {expand(L"%APPDATA%"), 3, false, {L"microsoft"}},
        {local, 3, false, {L"temp", L"microsoft", L"packages", L"programs", L"google", L"mozilla", L"npm-cache", L"pip"}},
        {expand(L"%ProgramData%"), 3, true, {L"microsoft", L"package cache", L"packages"}},
        {prof + L"\\Downloads", 3, true, {}},
        {prof + L"\\Desktop", 2, false, {}},
        {L"C:\\Users\\Public", 3, true, {}},
    };
    for (auto& r : roots) {
        if (out.size() >= cap || visited > 250000) { if (trunc) *trunc = true; break; }
        walk(r.path, 0, r.depth, r.dll, out, cap, r.skip, seen, visited);
    }
    if (out.size() >= cap && trunc) *trunc = true;
}

// ============================================================ категории
struct CatDef { const char* id; };
static const char* CAT_IDS[] = {"run_user", "run_sys", "run_wow", "runonce_user", "runonce_sys", "policies_run", "winlogon",
                                "startup_user", "startup_all", "tasks", "activesetup", "ifeo", "appinit",
                                "services", "processes", "network", "hosts", "defender",
                                "roaming", "temp", "programdata", "files", "custom"};

static bool collect(const string& cat, const wstring& arg, vector<WItem>& out, bool& trunc, string& err) {
    const wstring RUN = L"Software\\Microsoft\\Windows\\CurrentVersion\\Run";
    const wstring ONCE = L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce";
    if (cat == "run_user") colReg(out, HKEY_CURRENT_USER, RUN, 0);
    else if (cat == "run_sys") colReg(out, HKEY_LOCAL_MACHINE, RUN, 0);
    else if (cat == "run_wow") colReg(out, HKEY_LOCAL_MACHINE, L"Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run", 0);
    else if (cat == "runonce_user") colReg(out, HKEY_CURRENT_USER, ONCE, 0);
    else if (cat == "runonce_sys") colReg(out, HKEY_LOCAL_MACHINE, ONCE, 0);
    else if (cat == "policies_run") {
        const wstring P = L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run";
        colReg(out, HKEY_CURRENT_USER, P, 0);
        colReg(out, HKEY_LOCAL_MACHINE, P, 0);
    }
    else if (cat == "activesetup") colActiveSetup(out);
    else if (cat == "ifeo") colIfeo(out);
    else if (cat == "appinit") colAppInit(out);
    else if (cat == "network") colNetwork(out);
    else if (cat == "hosts") colHosts(out);
    else if (cat == "defender") {
        if (!g_defOn) { err = "Доступ к Защитнику Windows выключен в настройках"; return false; }
        colDefender(out);
    }
    else if (cat == "winlogon") colReg(out, HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", 0, true);
    else if (cat == "startup_user") listDir(out, expand(L"%AppData%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"), 2000, true, &trunc);
    else if (cat == "startup_all") listDir(out, expand(L"%ProgramData%\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp"), 2000, true, &trunc);
    else if (cat == "tasks") colTasks(out);
    else if (cat == "services") colServices(out);
    else if (cat == "processes") colProcesses(out);
    else if (cat == "roaming") listDir(out, expand(L"%AppData%"), 6000, false, &trunc);
    else if (cat == "temp") listDir(out, expand(L"%TEMP%"), 6000, false, &trunc);
    else if (cat == "programdata") listDir(out, expand(L"%ProgramData%"), 6000, false, &trunc);
    else if (cat == "files") colDeepFiles(out, &trunc);
    else if (cat == "custom") {
        wstring p = expand(trimW(arg));
        while (p.size() > 3 && (p.back() == L'\\' || p.back() == L'/')) p.pop_back();
        if (p.empty()) { err = "путь не указан"; return false; }
        DWORD a = GetFileAttributesW(p.c_str());
        if (a == INVALID_FILE_ATTRIBUTES || !(a & FILE_ATTRIBUTE_DIRECTORY)) { err = "папка не найдена"; return false; }
        listDir(out, p, 6000, false, &trunc);
    } else { err = "неизвестная категория"; return false; }
    return true;
}

// ============================================================ JSON
static string itemJson(const WItem& it) {
    string o = "{";
    auto kv = [&](const char* k, const string& v, bool last = false) { o += "\"" + string(k) + "\":" + v + (last ? "" : ","); };
    kv("id", std::to_string(it.id));
    kv("cat", "\"" + it.cat + "\"");
    kv("name", jstr(it.name));
    kv("sub", jstr(it.sub));
    kv("detail", jstr(it.detail));
    kv("path", jstr(it.exe));
    kv("full", jstr(it.full));
    kv("state", jstr(it.state));
    kv("start", jstr(it.start));
    kv("size", std::to_string(it.size));
    kv("mtime", jstr(it.mtime));
    kv("hidden", it.hidden ? "true" : "false");
    kv("dir", it.isDir ? "true" : "false");
    kv("pid", std::to_string(it.pid));
    kv("ppid", std::to_string(it.ppid));
    kv("parent", jstr(it.parent));
    kv("sig", "\"" + it.sig + "\"");
    bool wl = it.wl && g_wlOn;
    int risk = wl ? 0 : it.risk;
    kv("risk", std::to_string(risk));
    kv("level", string("\"") + levelOf(risk) + "\"");
    kv("wl", wl ? "true" : "false");
    kv("ack", it.ack ? "true" : "false");
    kv("ackAt", "\"" + jesc(it.ackAt) + "\"");
    kv("first", "\"" + jesc(it.first) + "\"");
    kv("isnew", it.isnew ? "true" : "false");
    kv("action", "\"" + it.action + "\"");
    o += "\"reasons\":[";
    if (wl) o += "\"В белом списке — ты отметил этот элемент как доверенный\"";
    else for (size_t i = 0; i < it.reasons.size(); i++) { if (i) o += ","; o += "\"" + jesc(it.reasons[i]) + "\""; }
    o += "]}";
    return o;
}

static string scanJson(const string& cat, const wstring& arg) {
    auto t0 = std::chrono::steady_clock::now();
    vector<WItem> v; bool trunc = false; string err;
    if (!collect(cat, arg, v, trunc, err))
        return "{\"ok\":false,\"error\":\"" + jesc(err) + "\"}";
    vector<string> gone;
    finishCat(v, cat, &gone);
    for (auto& it : v) it.id = g_nextId++;
    {
        std::lock_guard<std::mutex> lk(g_storeMx);
        for (long id : g_catIds[cat]) g_store.erase(id);
        g_catIds[cat].clear();
        for (auto& it : v) { g_catIds[cat].push_back(it.id); g_store[it.id] = it; }
    }
    long ms = (long)std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    string o = "{\"ok\":true,\"cat\":\"" + cat + "\",\"ms\":" + std::to_string(ms) +
               ",\"truncated\":" + (trunc ? "true" : "false") + ",\"items\":[";
    for (size_t i = 0; i < v.size(); i++) { if (i) o += ","; o += itemJson(v[i]); }
    o += "],\"gone\":[";
    for (size_t i = 0; i < gone.size() && i < 200; i++) { if (i) o += ","; o += "\"" + jesc(gone[i]) + "\""; }
    o += "]}";
    return o;
}

// ============================================================ действия
static thread_local string g_qLast;   // имя файла в карантине после последнего успешного переноса
static bool quarantineItem(const wstring& p, bool isDir, string& err) {
    g_qLast.clear();
    if (isSysPath(lowerW(p))) { err = "защищённый системный путь"; return false; }
    if (!fileExists(p)) { err = "объект уже отсутствует"; return false; }
    wstring dir = g_exeDir + L"\\Quarantine";
    CreateDirectoryW(dir.c_str(), nullptr);
    SYSTEMTIME t; GetLocalTime(&t);
    wchar_t ts[40];
    swprintf(ts, 40, L"%04d%02d%02d-%02d%02d%02d__", t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute, t.wSecond);
    wstring dest = dir + L"\\" + ts + baseName(p) + L".quarantine";
    if (isDir) {
        std::error_code ec;
        fs::rename(p, dest, ec);
        if (ec) {
            ec.clear();
            fs::copy(p, dest, fs::copy_options::recursive, ec);
            if (ec) { err = ec.message(); return false; }
            fs::remove_all(p, ec);
        }
    } else if (!MoveFileExW(p.c_str(), dest.c_str(), MOVEFILE_COPY_ALLOWED)) {
        err = "код ошибки " + std::to_string(GetLastError());
        return false;
    }
    g_qLast = u8(baseName(dest));
    FILE* f = _wfopen((dest + L".origin.txt").c_str(), L"wb");
    if (f) { string o = u8(p); fwrite(o.data(), 1, o.size(), f); fclose(f); }
    return true;
}

static bool applyAction(const WItem& it, string& err) {
    if (it.action == "quarantine") return quarantineItem(it.del.path, it.isDir, err);
    if (it.action == "kill") {
        static const set<wstring> crit = {L"system", L"smss.exe", L"csrss.exe", L"wininit.exe", L"winlogon.exe",
                                          L"services.exe", L"lsass.exe", L"registry", L"memory compression"};
        if (it.pid <= 4 || crit.count(lowerW(it.name))) { err = "критический системный процесс — завершение запрещено"; return false; }
        if (it.pid == GetCurrentProcessId()) { err = "это сам сканер"; return false; }
    }
    if (it.action.empty()) { err = "для этого элемента действие недоступно"; return false; }
    return deleteItem(it.del, err);
}

// окончательное удаление файла или папки (без карантина)
static bool purgePath(const wstring& p, bool isDir, string& err) {
    if (p.empty()) { err = "у элемента нет файла на диске"; return false; }
    if (isSysPath(lowerW(p))) { err = "защищённый системный путь"; return false; }
    if (!fileExists(p)) { err = "файл уже отсутствует"; return false; }
    wchar_t me[MAX_PATH]; GetModuleFileNameW(nullptr, me, MAX_PATH);
    if (lowerW(p) == lowerW(me)) { err = "это сам сканер"; return false; }
    std::error_code ec;
    if (isDir) { fs::remove_all(p, ec); if (ec) { err = ec.message(); return false; } return true; }
    SetFileAttributesW(p.c_str(), FILE_ATTRIBUTE_NORMAL);
    if (!DeleteFileW(p.c_str())) {
        DWORD e = GetLastError();
        err = e == 32 ? "файл занят — его использует запущенная программа (сначала заверши процесс)" : e == 5 ? "нет доступа (запусти от администратора)" : "код ошибки " + std::to_string(e);
        return false;
    }
    return true;
}

static string removeJson(const string& idsCsv, const string& mode) {
    string o = "{\"results\":[";
    bool first = true;
    size_t pos = 0;
    while (pos <= idsCsv.size()) {
        size_t c = idsCsv.find(',', pos);
        string tok = idsCsv.substr(pos, c == string::npos ? string::npos : c - pos);
        pos = c == string::npos ? idsCsv.size() + 1 : c + 1;
        if (tok.empty()) continue;
        long id = atol(tok.c_str());
        WItem it; bool found = false;
        {
            std::lock_guard<std::mutex> lk(g_storeMx);
            auto f = g_store.find(id);
            if (f != g_store.end()) { it = f->second; found = true; }
        }
        string err; bool ok = false;
        if (!found) err = "элемент не найден — обнови список";
        else if (mode == "purge") {
            wstring p = it.action == "quarantine" ? it.del.path : (!it.full.empty() ? it.full : it.exe);
            ok = purgePath(p, it.isDir, err);
        } else {
            g_qLast.clear();
            ok = applyAction(it, err);
        }
        string warn;
        if (ok && mode == "both" && !it.exe.empty() && it.action != "quarantine") {
            string e2;
            if (!purgePath(it.exe, false, e2)) warn = "запись удалена, но файл не удалён: " + e2;
        }
        if (found) jlog(ok ? "action" : "error", string(ok ? (mode == "purge" ? "Файл удалён навсегда: " : mode == "both" ? "Запись и файл удалены: " : "Действие «") : "Не удалось выполнить «") +
                        (mode == "purge" || mode == "both" ? string() : it.action + "»: ") + itemLabel(it) + (ok ? (warn.empty() ? "" : " (" + warn + ")") : " (" + err + ")"),
                        ok && mode.empty() && it.action == "quarantine" && !g_qLast.empty() ? "q:" + g_qLast : "");
        if (ok) {
            std::lock_guard<std::mutex> lk(g_storeMx);
            g_store.erase(id);
        }
        if (!first) o += ",";
        first = false;
        o += "{\"id\":" + std::to_string(id) + ",\"ok\":" + (ok ? "true" : "false") + ",\"error\":\"" + jesc(err) + "\",\"warn\":\"" + jesc(warn) + "\"}";
    }
    return o + "]}";
}

static string revealJson(long id) {
    WItem it; bool found = false;
    {
        std::lock_guard<std::mutex> lk(g_storeMx);
        auto f = g_store.find(id);
        if (f != g_store.end()) { it = f->second; found = true; }
    }
    wstring p = !it.full.empty() ? it.full : it.exe;
    if (!found || p.empty() || !fileExists(p)) return "{\"ok\":false,\"error\":\"у элемента нет файла на диске\"}";
    wstring args = L"/select,\"" + p + L"\"";
    ShellExecuteW(nullptr, L"open", L"explorer.exe", args.c_str(), nullptr, SW_SHOWNORMAL);
    return "{\"ok\":true}";
}

// ============================================================ проверка обновлений (GitHub Releases)
// Единственный исходящий запрос приложения: GET https://api.github.com/repos/<repo>/releases/latest.
// Ничего о пользователе не передаётся. Отключается в настройках (поле "updates": false в settings.json).
static const char* UPD_REPO = "user110611/SimpleWarnAnalyzer";
static string httpsGet(const wchar_t* host, const wstring& path) {
    string out;
    HINTERNET ses = WinHttpOpen(L"SimpleWarnAnalyzer", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!ses) return out;
    WinHttpSetTimeouts(ses, 5000, 5000, 8000, 8000);
    HINTERNET con = WinHttpConnect(ses, host, INTERNET_DEFAULT_HTTPS_PORT, 0);
    HINTERNET req = con ? WinHttpOpenRequest(con, L"GET", path.c_str(), NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE) : NULL;
    if (req && WinHttpSendRequest(req, L"Accept: application/vnd.github+json\r\n", (DWORD)-1L, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) && WinHttpReceiveResponse(req, NULL)) {
        DWORD code = 0, sz = sizeof(code);
        WinHttpQueryHeaders(req, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &code, &sz, WINHTTP_NO_HEADER_INDEX);
        if (code == 200) {
            for (;;) {
                DWORD n = 0;
                if (!WinHttpQueryDataAvailable(req, &n) || !n) break;
                string b(n, '\0'); DWORD r = 0;
                if (!WinHttpReadData(req, &b[0], n, &r) || !r) break;
                out.append(b, 0, r);
                if (out.size() > 2000000) break;
            }
        }
    }
    if (req) WinHttpCloseHandle(req);
    if (con) WinHttpCloseHandle(con);
    WinHttpCloseHandle(ses);
    return out;
}
static string jsonStrAt(const string& j, size_t p) {   // p — позиция сразу после открывающей кавычки
    string v;
    for (; p < j.size() && j[p] != '"'; p++) { if (j[p] == '\\' && p + 1 < j.size()) p++; v += j[p]; }
    return v;
}
static string jsonField(const string& j, const string& key) {
    string k = "\"" + key + "\":\"";
    size_t p = j.find(k);
    return p == string::npos ? "" : jsonStrAt(j, p + k.size());
}
static vector<int> parseVer(string v) {
    if (!v.empty() && (v[0] == 'v' || v[0] == 'V')) v = v.substr(1);
    vector<int> r; int cur = 0; bool any = false;
    for (char c : v) {
        if (c >= '0' && c <= '9') { cur = cur * 10 + (c - '0'); any = true; }
        else if (c == '.') { r.push_back(cur); cur = 0; any = false; }
        else break;
    }
    if (any) r.push_back(cur);
    return r;
}
static bool verNewer(const string& a, const string& b) {   // a новее b
    auto x = parseVer(a), y = parseVer(b);
    if (x.empty()) return false;
    size_t n = std::max(x.size(), y.size());
    for (size_t i = 0; i < n; i++) {
        int p = i < x.size() ? x[i] : 0, q = i < y.size() ? y[i] : 0;
        if (p != q) return p > q;
    }
    return false;
}
static string updateJson() {
    if (g_updOff) return "{\"enabled\":false}";
    static std::mutex mx; static string cache; static std::chrono::steady_clock::time_point at; static bool okCache = false;
    std::lock_guard<std::mutex> lk(mx);
    auto now = std::chrono::steady_clock::now();
    auto ttl = okCache ? std::chrono::hours(6) : std::chrono::minutes(10);
    if (!cache.empty() && now - at < ttl) return cache;
    string j = httpsGet(L"api.github.com", wstring(L"/repos/") + wstring(UPD_REPO, UPD_REPO + strlen(UPD_REPO)) + L"/releases/latest");
    string tag = jsonField(j, "tag_name");
    string prefix = string("https://github.com/") + UPD_REPO + "/";
    string page = jsonField(j, "html_url"), dl;
    size_t p = 0;
    while ((p = j.find("\"browser_download_url\":\"", p)) != string::npos) {
        p += 24;
        string u = jsonStrAt(j, p);
        if (u.size() > 4 && u.compare(u.size() - 4, 4, ".exe") == 0) { dl = u; break; }
    }
    // ссылки отдаём только на наш репозиторий
    if (page.rfind(prefix, 0) != 0) page = prefix + "releases/latest";
    if (dl.rfind(prefix, 0) != 0) dl = page;
    bool ok = !tag.empty();
    cache = string("{\"enabled\":true,\"ok\":") + (ok ? "true" : "false") + ",\"cur\":\"" + APP_VERSION + "\",\"latest\":\"" + jesc(tag) +
            "\",\"newer\":" + (ok && verNewer(tag, APP_VERSION) ? "true" : "false") + ",\"url\":\"" + jesc(page) + "\",\"dl\":\"" + jesc(dl) + "\"}";
    okCache = ok; at = now;
    return cache;
}

// ============================================================ настройки / белый список / Defender (API)
static string settingsJson() {
    std::lock_guard<std::mutex> lk(g_cfgMx);
    string o = string("{\"whitelist\":") + (g_wlOn ? "true" : "false") + ",\"defender\":" + (g_defOn ? "true" : "false") +
               ",\"updates\":" + (g_updOff ? "false" : "true") + ",\"entries\":[";
    for (size_t i = 0; i < g_wl.size(); i++) {
        auto& e = g_wl[i];
        if (i) o += ",";
        o += "{\"key\":\"" + jesc(e.key) + "\",\"name\":" + jstr(e.name) + ",\"date\":\"" + jesc(e.date) +
             "\",\"path\":\"" + jesc(e.key[0] == 'p' ? e.key.substr(2) : "") + "\",\"hash\":" + (e.hash.empty() ? "false" : "true") + "}";
    }
    return o + "]}";
}

// add=true: добавить в белый список; false: убрать. Ищет по id элементов или по готовому ключу.
static string trustJson(const string& idsCsv, bool add, const string& keyArg) {
    set<string> keys;
    vector<string> hashes;
    string res = "{\"items\":[";
    {
        std::lock_guard<std::mutex> lk(g_storeMx);
        map<string, WItem*> byKey;
        if (!keyArg.empty()) keys.insert(keyArg);
        size_t pos = 0;
        while (pos <= idsCsv.size() && !idsCsv.empty()) {
            size_t c = idsCsv.find(',', pos);
            string tok = idsCsv.substr(pos, c == string::npos ? string::npos : c - pos);
            pos = c == string::npos ? idsCsv.size() + 1 : c + 1;
            auto f = g_store.find(atol(tok.c_str()));
            if (f == g_store.end()) continue;
            string k = wlKey(f->second);
            if (keys.insert(k).second && add) {
                WlEntry e; e.key = k; e.name = f->second.name;
                e.hash = k[0] == 'p' ? sha256File(f->second.exe) : "";
                SYSTEMTIME t; GetLocalTime(&t);
                char d[32]; snprintf(d, 32, "%04d-%02d-%02d", t.wYear, t.wMonth, t.wDay);
                e.date = d;
                std::lock_guard<std::mutex> lc(g_cfgMx);
                g_wl.erase(std::remove_if(g_wl.begin(), g_wl.end(), [&](const WlEntry& x) { return x.key == k; }), g_wl.end());
                g_wl.push_back(e);
                jlog("trust", "Добавлено в белый список: " + itemLabel(f->second), "trust:" + k);
            }
        }
        if (!add) {
            for (auto& kv : g_store) if (keys.count(wlKey(kv.second))) jlog("trust", "Убрано из белого списка: " + itemLabel(kv.second));
            std::lock_guard<std::mutex> lc(g_cfgMx);
            g_wl.erase(std::remove_if(g_wl.begin(), g_wl.end(), [&](const WlEntry& x) { return keys.count(x.key) > 0; }), g_wl.end());
        }
        bool first = true;
        for (auto& kv : g_store) {
            if (!keys.count(wlKey(kv.second))) continue;
            kv.second.wl = add;
            if (!first) res += ",";
            first = false;
            res += itemJson(kv.second);
        }
    }
    { std::lock_guard<std::mutex> lc(g_cfgMx); saveWl(); }
    return res + "]}";
}

// ---------- управление настройками Защитника: исключения и контролируемый доступ к папкам ----------
static string jarr(const vector<wstring>& v) {
    string o = "[";
    for (size_t i = 0; i < v.size(); i++) { if (i) o += ","; o += jstr(v[i]); }
    return o + "]";
}

static string defPrefsJson() {
    if (!g_defOn) return "{\"ok\":false,\"error\":\"Доступ к Защитнику Windows выключен в настройках\"}";
    const wstring script =
        L"[Console]::OutputEncoding=[Text.Encoding]::UTF8;$ErrorActionPreference='SilentlyContinue';"
        L"$p=Get-MpPreference;if(-not $p){'ERR|nodata'}else{"
        L"'CFA|'+$p.EnableControlledFolderAccess;"
        L"foreach($x in $p.ExclusionPath){if($x){'XP|'+$x}};foreach($x in $p.ExclusionExtension){if($x){'XE|'+$x}};"
        L"foreach($x in $p.ExclusionProcess){if($x){'XR|'+$x}};"
        L"foreach($x in $p.ControlledFolderAccessProtectedFolders){if($x){'PF|'+$x}};"
        L"foreach($x in $p.ControlledFolderAccessAllowedApplications){if($x){'AA|'+$x}}}";
    string o = runPs(script);
    map<string, vector<wstring>> m;
    string cfa = "?"; bool hidden = false, nodata = false;
    size_t pos = 0;
    while (pos < o.size()) {
        size_t e = o.find('\n', pos);
        string ln = o.substr(pos, e == string::npos ? string::npos : e - pos);
        pos = e == string::npos ? o.size() : e + 1;
        while (!ln.empty() && (ln.back() == '\r' || ln.back() == ' ')) ln.pop_back();
        size_t bar = ln.find('|');
        if (bar == string::npos) continue;
        string k = ln.substr(0, bar), v = ln.substr(bar + 1);
        if (k == "ERR") nodata = true;
        else if (k == "CFA") cfa = v;
        else if (v.rfind("N/A", 0) == 0) hidden = true;
        else m[k].push_back(toWide(v));
    }
    if (nodata) return "{\"ok\":false,\"error\":\"Защитник Windows недоступен или отключён политикой\"}";
    return string("{\"ok\":true,\"admin\":") + (isElevated() ? "true" : "false") + ",\"hidden\":" + (hidden ? "true" : "false") +
           ",\"cfa\":\"" + jesc(cfa) + "\",\"xp\":" + jarr(m["XP"]) + ",\"xe\":" + jarr(m["XE"]) + ",\"xr\":" + jarr(m["XR"]) +
           ",\"pf\":" + jarr(m["PF"]) + ",\"aa\":" + jarr(m["AA"]) + "}";
}

static string defChangeJson(const string& kind, const string& op, const wstring& valIn) {
    auto err = [](const string& e) { return "{\"ok\":false,\"error\":\"" + jesc(e) + "\"}"; };
    if (!g_defOn) return err("Доступ к Защитнику Windows выключен в настройках");
    if (!isElevated()) return err("Нужны права администратора: запусти сканер от администратора (кнопка «Повысить»)");
    const wchar_t* param = kind == "xp" ? L"ExclusionPath" : kind == "xe" ? L"ExclusionExtension" :
                           kind == "xr" ? L"ExclusionProcess" : kind == "pf" ? L"ControlledFolderAccessProtectedFolders" :
                           kind == "aa" ? L"ControlledFolderAccessAllowedApplications" : nullptr;
    if (!param) return err("неизвестный список");
    if (op != "add" && op != "remove") return err("неизвестное действие");
    wstring v = trimW(valIn);
    if (kind == "xe") {                              // расширение: без точки и звёздочки
        while (!v.empty() && (v[0] == L'.' || v[0] == L'*')) v.erase(0, 1);
        if (v.empty() || v.size() > 15) return err("укажи расширение, например exe");
        for (wchar_t c : v) if (!std::iswalnum(c) && c != L'_' && c != L'-') return err("в расширении допустимы только буквы и цифры");
    }
    if (v.empty() || v.size() > 500) return err("пустое или слишком длинное значение");
    for (wchar_t c : v)
        if (c < 0x20 || c == 0x2018 || c == 0x2019 || c == 0x201A || c == 0x201B)
            return err("в значении есть недопустимые символы");
    wstring q;
    for (wchar_t c : v) { if (c == L'\'') q += L"''"; else q += c; }
    wstring script = L"[Console]::OutputEncoding=[Text.Encoding]::UTF8;try{" + wstring(op == "add" ? L"Add" : L"Remove") +
                     L"-MpPreference -" + param + L" @('" + q + L"') -ErrorAction Stop;'OK'}catch{'ERR|'+$_.Exception.Message}";
    string o = runPs(script);
    if (o.rfind("OK", 0) == 0 || o.find("\nOK") != string::npos) {
        jlog("defender", string(op == "add" ? "Защитник: добавлено" : "Защитник: удалено") + " [" + kind + "] " + u8(v));
        return "{\"ok\":true}";
    }
    size_t p = o.find("ERR|");
    string msg = p == string::npos ? "Защитник не принял изменение (возможно, включена защита от подделки)" : o.substr(p + 4);
    while (!msg.empty() && (msg.back() == '\n' || msg.back() == '\r')) msg.pop_back();
    return err(msg);
}

// отметить элементы прочитанными / вернуть в непрочитанные; возвращает обновлённые элементы
static string ackJson(const string& idsCsv, bool on) {
    set<string> keys;
    map<string, string> lbls;
    string res = "{\"items\":[";
    {
        std::lock_guard<std::mutex> lk(g_storeMx);
        size_t pos = 0;
        while (pos <= idsCsv.size() && !idsCsv.empty()) {
            size_t c = idsCsv.find(',', pos);
            string tok = idsCsv.substr(pos, c == string::npos ? string::npos : c - pos);
            pos = c == string::npos ? idsCsv.size() + 1 : c + 1;
            auto f = g_store.find(atol(tok.c_str()));
            if (f != g_store.end()) { string k = wlKey(f->second); keys.insert(k); lbls[k] = itemLabel(f->second); }
        }
        {
            std::lock_guard<std::mutex> lc(g_cfgMx);
            string d = nowStamp();
            for (auto& k : keys) { if (on) { g_ack[k] = d; g_ackLbl[k] = lbls[k]; } else { g_ack.erase(k); g_ackLbl.erase(k); } }
            saveAcks();
        }
        bool first = true;
        for (auto& kv : g_store) {
            if (!keys.count(wlKey(kv.second))) continue;
            kv.second.ack = on;
            kv.second.ackAt = on ? nowStamp() : "";
            jlog("ack", string(on ? "В архив (прочитано): " : "Возвращено из архива: ") + itemLabel(kv.second), on ? "ack:" + wlKey(kv.second) : "");
            if (!first) res += ",";
            first = false;
            res += itemJson(kv.second);
        }
    }
    return res + "]}";
}

// ---------- редактирование файла hosts: добавить / изменить / удалить запись (перед правкой делается копия) ----------
static string normHostsLine(const string& line) {   // без комментария, пробелы схлопнуты
    string l = line;
    size_t h = l.find('#'); if (h != string::npos) l.resize(h);
    string o; bool sp = false;
    for (unsigned char c : l) {
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') sp = true;
        else { if (sp && !o.empty()) o += ' '; sp = false; o += (char)c; }
    }
    return o;
}
static string hostsChangeJson(const string& op, const string& oldLine, const string& ipIn, const string& namesIn) {
    auto err = [](const string& e) { return "{\"ok\":false,\"error\":\"" + jesc(e) + "\"}"; };
    if (op != "add" && op != "edit" && op != "remove") return err("неизвестное действие");
    if (!isElevated()) return err("Нужны права администратора: запусти сканер от администратора (кнопка «Повысить»)");
    string newLine;
    if (op != "remove") {
        string ip = normHostsLine(ipIn), names = normHostsLine(namesIn);
        in_addr a4; in6_addr a6;
        if (ip.empty() || ip.find(' ') != string::npos || (inet_pton(AF_INET, ip.c_str(), &a4) != 1 && inet_pton(AF_INET6, ip.c_str(), &a6) != 1))
            return err("некорректный IP-адрес, например 127.0.0.1");
        if (names.empty()) return err("укажи имя сайта, например example.com");
        size_t p = 0;
        while (p <= names.size()) {
            size_t sp = names.find(' ', p);
            string t = names.substr(p, sp == string::npos ? string::npos : sp - p);
            p = sp == string::npos ? names.size() + 1 : sp + 1;
            if (t.empty() || t.size() > 253) return err("слишком длинное или пустое имя сайта");
            for (unsigned char c : t) if (!(std::isalnum(c) || c == '.' || c == '-' || c == '_' || c == '*')) return err("в имени сайта допустимы буквы, цифры, точка, дефис и подчёркивание");
        }
        newLine = ip + "\t" + names;
    }
    wstring path = g_winOrig + L"\\System32\\drivers\\etc\\hosts";
    string s = readFileStr(path);
    vector<string> lines; size_t pos = 0;
    while (pos < s.size()) {
        size_t e = s.find('\n', pos);
        string ln = s.substr(pos, e == string::npos ? string::npos : e - pos);
        pos = e == string::npos ? s.size() : e + 1;
        while (!ln.empty() && ln.back() == '\r') ln.pop_back();
        lines.push_back(ln);
    }
    string newN = normHostsLine(newLine), oldN = normHostsLine(oldLine);
    bool done = false;
    if (op == "add") {
        for (auto& ln : lines) if (normHostsLine(ln) == newN) return err("такая запись уже есть");
        lines.push_back(newLine); done = true;
    } else {
        if (oldN.empty()) return err("не указана запись");
        for (size_t i = 0; i < lines.size();) {
            if (normHostsLine(lines[i]) != oldN) { i++; continue; }
            if (op == "remove") { lines.erase(lines.begin() + i); done = true; continue; }
            if (!done) { lines[i] = newLine; done = true; i++; } else i++;
        }
        if (!done) return err("запись не найдена — обнови список");
    }
    wstring bdir = g_exeDir + L"\\hosts_backups";
    CreateDirectoryW(bdir.c_str(), nullptr);
    string st = nowStamp(); string tag;
    for (char c : st) if (c != '-' && c != ':') tag += (c == ' ' ? '_' : c);
    if (!s.empty() && !CopyFileW(path.c_str(), (bdir + L"\\hosts-" + toWide(tag) + L".bak").c_str(), FALSE))
        return err("не удалось сохранить копию hosts — изменение отменено");
    string out;
    for (auto& ln : lines) out += ln + "\r\n";
    FILE* f = _wfopen(path.c_str(), L"wb");
    if (!f) return err("не удалось записать hosts (файл защищён или занят другой программой)");
    fwrite(out.data(), 1, out.size(), f);
    fclose(f);
    jlog("hosts", string(op == "add" ? "hosts: добавлена запись " : op == "edit" ? "hosts: изменена запись «" + oldN + "» → " : "hosts: удалена запись ") +
                  (op == "remove" ? oldN : newN), s.empty() ? "" : "hosts:hosts-" + tag + ".bak");
    return "{\"ok\":true}";
}

// ---------- карантин: просмотр, возврат, удаление ----------
static bool qNameOk(const string& n) {
    if (n.empty() || n.size() > 260 || n.find_first_of("\\/:") != string::npos || n.find("..") != string::npos) return false;
    return n.size() > 11 && n.compare(n.size() - 11, 11, ".quarantine") == 0;
}
static string quarantineListJson() {
    wstring dir = g_exeDir + L"\\Quarantine";
    string o = "{\"ok\":true,\"dir\":" + jstr(dir) + ",\"items\":[";
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW((dir + L"\\*.quarantine").c_str(), &fd);
    bool first = true;
    if (h != INVALID_HANDLE_VALUE) {
        do {
            wstring fn = fd.cFileName;
            bool isDir = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
            long long sz = isDir ? -1 : (((long long)fd.nFileSizeHigh << 32) | fd.nFileSizeLow);
            wstring nm = fn.substr(0, fn.size() - 11), when;
            size_t us = nm.find(L"__");
            if (nm.size() > 17 && us == 15) {
                when = nm.substr(0, 4) + L"-" + nm.substr(4, 2) + L"-" + nm.substr(6, 2) + L" " + nm.substr(9, 2) + L":" + nm.substr(11, 2) + L":" + nm.substr(13, 2);
                nm = nm.substr(17);
            }
            string origin = readFileStr(dir + L"\\" + fn + L".origin.txt");
            if (!first) o += ",";
            first = false;
            o += "{\"file\":" + jstr(fn) + ",\"name\":" + jstr(nm) + ",\"when\":" + jstr(when) + ",\"origin\":\"" + jesc(origin) +
                 "\",\"size\":" + std::to_string(sz) + ",\"dir\":" + (isDir ? "true" : "false") + "}";
        } while (FindNextFileW(h, &fd));
        FindClose(h);
    }
    return o + "]}";
}
static string quarantineActJson(const string& file, const string& op) {
    auto err = [](const string& e) { return "{\"ok\":false,\"error\":\"" + jesc(e) + "\"}"; };
    wstring dir = g_exeDir + L"\\Quarantine";
    if (op == "openfolder") {
        CreateDirectoryW(dir.c_str(), nullptr);
        ShellExecuteW(nullptr, L"open", dir.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
        return "{\"ok\":true}";
    }
    if (op == "empty") {
        int n = 0;
        WIN32_FIND_DATAW fd;
        HANDLE h = FindFirstFileW((dir + L"\\*").c_str(), &fd);
        vector<wstring> all;
        if (h != INVALID_HANDLE_VALUE) { do { wstring f = fd.cFileName; if (f != L"." && f != L"..") all.push_back(f); } while (FindNextFileW(h, &fd)); FindClose(h); }
        for (auto& f : all) {
            std::error_code ec; fs::remove_all(dir + L"\\" + f, ec);
            if (!ec && f.size() > 11 && f.compare(f.size() - 11, 11, L".quarantine") == 0) n++;
        }
        jlog("action", "Карантин очищен (объектов: " + std::to_string(n) + ")");
        return "{\"ok\":true}";
    }
    if (!qNameOk(file)) return err("некорректное имя");
    wstring wf = toWide(file), full = dir + L"\\" + wf;
    if (!fileExists(full)) return err("объект не найден в карантине — обнови список");
    bool isDir = (GetFileAttributesW(full.c_str()) & FILE_ATTRIBUTE_DIRECTORY) != 0;
    string origin = readFileStr(full + L".origin.txt");
    while (!origin.empty() && (origin.back() == '\n' || origin.back() == '\r')) origin.pop_back();
    if (op == "open") {
        wstring args = L"/select,\"" + full + L"\"";
        ShellExecuteW(nullptr, L"open", L"explorer.exe", args.c_str(), nullptr, SW_SHOWNORMAL);
        return "{\"ok\":true}";
    }
    if (op == "delete") {
        std::error_code ec; fs::remove_all(full, ec);
        if (ec) return err(ec.message());
        DeleteFileW((full + L".origin.txt").c_str());
        jlog("action", "Удалено из карантина навсегда: " + file + (origin.empty() ? "" : " (было: " + origin + ")"));
        return "{\"ok\":true}";
    }
    if (op == "restore") {
        wstring dest = toWide(origin);
        if (dest.empty()) return err("неизвестно, откуда файл — вернуть нельзя (удали или забери вручную из папки Quarantine)");
        if (isSysPath(lowerW(dest))) return err("защищённый системный путь");
        if (fileExists(dest)) return err("по этому пути уже есть файл: " + origin);
        std::error_code ec;
        fs::create_directories(fs::path(dest).parent_path(), ec);
        if (isDir) { fs::rename(full, dest, ec); if (ec) { ec.clear(); fs::copy(full, dest, fs::copy_options::recursive, ec); if (!ec) fs::remove_all(full, ec); } if (ec) return err(ec.message()); }
        else if (!MoveFileExW(full.c_str(), dest.c_str(), MOVEFILE_COPY_ALLOWED)) return err("код ошибки " + std::to_string(GetLastError()));
        DeleteFileW((full + L".origin.txt").c_str());
        jlog("action", "Возвращено из карантина: " + origin);
        return "{\"ok\":true}";
    }
    return err("неизвестное действие");
}

// ---------- отмена действия из журнала ----------
static string undoJson(const string& token) {
    auto err = [](const string& e) { return "{\"ok\":false,\"error\":\"" + jesc(e) + "\"}"; };
    size_t c = token.find(':');
    if (c == string::npos) return err("это действие нельзя отменить");
    string kind = token.substr(0, c), arg = token.substr(c + 1);
    string res;
    if (kind == "q") {
        res = quarantineActJson(arg, "restore");
    } else if (kind == "ack") {
        string ids;
        {
            std::lock_guard<std::mutex> lk(g_storeMx);
            for (auto& kv : g_store) if (wlKey(kv.second) == arg) ids += (ids.empty() ? "" : ",") + std::to_string(kv.first);
        }
        if (ids.empty()) {
            std::lock_guard<std::mutex> lc(g_cfgMx);
            g_ack.erase(arg); g_ackLbl.erase(arg); saveAcks();
            res = "{\"items\":[]}";
        } else res = ackJson(ids, false);
    } else if (kind == "trust") {
        res = trustJson("", false, arg);
    } else if (kind == "hosts") {
        if (!isElevated()) return err("Нужны права администратора: запусти сканер от администратора (кнопка «Повысить»)");
        if (arg.find_first_of("\\/:") != string::npos || arg.find("..") != string::npos || arg.compare(0, 6, "hosts-") != 0) return err("некорректное имя копии");
        wstring bak = g_exeDir + L"\\hosts_backups\\" + toWide(arg);
        if (!fileExists(bak)) return err("копия файла hosts не найдена");
        wstring path = g_winOrig + L"\\System32\\drivers\\etc\\hosts";
        if (!CopyFileW(bak.c_str(), path.c_str(), FALSE)) return err("не удалось восстановить hosts (код " + std::to_string(GetLastError()) + ")");
        res = "{\"ok\":true}";
    } else return err("это действие нельзя отменить");
    if (res.find("\"ok\":false") != string::npos) return res;
    jlog("undo", "Отменено действие", token);
    if (res.rfind("{\"ok\":true", 0) == 0) return res;
    return res;
}

static wstring findMpCmd() {
    wstring base = expand(L"%ProgramData%\\Microsoft\\Windows Defender\\Platform"), best;
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW((base + L"\\*").c_str(), &fd);
    if (h != INVALID_HANDLE_VALUE) {
        do {
            if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) && fd.cFileName[0] != L'.') {
                wstring c = base + L"\\" + fd.cFileName + L"\\MpCmdRun.exe";
                if (fileExists(c) && c > best) best = c;
            }
        } while (FindNextFileW(h, &fd));
        FindClose(h);
    }
    if (best.empty()) {
        wstring c = expand(L"%ProgramFiles%\\Windows Defender\\MpCmdRun.exe");
        if (fileExists(c)) best = c;
    }
    return best;
}

static string defScanJson(long id) {
    if (!g_defOn) return "{\"ok\":false,\"error\":\"Доступ к Защитнику Windows выключен в настройках\"}";
    WItem it; bool found = false;
    {
        std::lock_guard<std::mutex> lk(g_storeMx);
        auto f = g_store.find(id);
        if (f != g_store.end()) { it = f->second; found = true; }
    }
    wstring p = !it.full.empty() ? it.full : it.exe;
    if (!found || p.empty() || !fileExists(p) || p.find(L'"') != wstring::npos)
        return "{\"ok\":false,\"error\":\"у элемента нет файла на диске\"}";
    wstring mp = findMpCmd();
    if (mp.empty()) return "{\"ok\":false,\"error\":\"MpCmdRun.exe не найден — Защитник Windows недоступен\"}";
    wstring cmd = L"\"" + mp + L"\" -Scan -ScanType 3 -File \"" + p + L"\" -DisableRemediation";
    STARTUPINFOW si{}; si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    vector<wchar_t> b(cmd.begin(), cmd.end()); b.push_back(0);
    if (!CreateProcessW(nullptr, b.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi))
        return "{\"ok\":false,\"error\":\"не удалось запустить проверку\"}";
    DWORD w = WaitForSingleObject(pi.hProcess, 180000), code = 1;
    if (w == WAIT_TIMEOUT) TerminateProcess(pi.hProcess, 1);
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    const char* r = w == WAIT_TIMEOUT ? "timeout" : code == 0 ? "clean" : code == 2 ? "threat" : "error";
    return string("{\"ok\":true,\"result\":\"") + r + "\",\"code\":" + std::to_string(code) + "}";
}

// ============================================================ HTTP
static string urlDecode(const string& s) {
    string o;
    for (size_t i = 0; i < s.size(); i++) {
        if (s[i] == '%' && i + 2 < s.size() + 0 && isxdigit((unsigned char)s[i + 1]) && isxdigit((unsigned char)s[i + 2])) {
            o += (char)strtol(s.substr(i + 1, 2).c_str(), nullptr, 16);
            i += 2;
        } else if (s[i] == '+') o += ' ';
        else o += s[i];
    }
    return o;
}
static map<string, string> parseQuery(const string& q) {
    map<string, string> m;
    size_t pos = 0;
    while (pos < q.size()) {
        size_t amp = q.find('&', pos);
        string pair = q.substr(pos, amp == string::npos ? string::npos : amp - pos);
        pos = amp == string::npos ? q.size() : amp + 1;
        size_t eq = pair.find('=');
        if (eq == string::npos) m[urlDecode(pair)] = "";
        else m[urlDecode(pair.substr(0, eq))] = urlDecode(pair.substr(eq + 1));
    }
    return m;
}

static void sendAll(SOCKET s, const string& d) {
    size_t off = 0;
    while (off < d.size()) {
        int n = send(s, d.data() + off, (int)std::min<size_t>(d.size() - off, 1 << 16), 0);
        if (n <= 0) return;
        off += n;
    }
}
static void reply(SOCKET s, int code, const char* ctype, const string& body) {
    const char* st = code == 200 ? "OK" : code == 204 ? "No Content" : code == 400 ? "Bad Request" :
                     code == 403 ? "Forbidden" : code == 404 ? "Not Found" : "Error";
    string h = "HTTP/1.1 " + std::to_string(code) + " " + st + "\r\nContent-Type: " + ctype +
               "\r\nContent-Length: " + std::to_string(body.size()) +
               "\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY"
               "\r\nReferrer-Policy: no-referrer\r\nConnection: close\r\n";
    h += "Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'\r\n\r\n";
    sendAll(s, h + body);
}

static string readUi() {
    FILE* f = _wfopen((g_exeDir + L"\\ui.html").c_str(), L"rb");
    string html;
    if (f) {
        char b[8192]; size_t n;
        while ((n = fread(b, 1, sizeof b, f)) > 0) html.append(b, n);
        fclose(f);
    } else html = UI_HTML;
    size_t p = html.find("__TOKEN__");
    if (p != string::npos) html.replace(p, 9, g_token);
    return html;
}

static wstring g_selfExe;

static void handleClient(SOCKET s) {
    DWORD to = 15000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char*)&to, sizeof to);
    string req; char buf[8192];
    size_t hdrEnd = string::npos;
    while (req.size() < (1 << 16)) {
        int n = recv(s, buf, sizeof buf, 0);
        if (n <= 0) break;
        req.append(buf, n);
        hdrEnd = req.find("\r\n\r\n");
        if (hdrEnd != string::npos) break;
    }
    if (hdrEnd == string::npos) { closesocket(s); return; }
    string head = req.substr(0, hdrEnd), body = req.substr(hdrEnd + 4);
    size_t le = head.find("\r\n");
    string line = head.substr(0, le);
    map<string, string> hd;
    size_t p = le;
    while (p != string::npos && p + 2 < head.size()) {
        size_t e = head.find("\r\n", p + 2);
        string l = head.substr(p + 2, e == string::npos ? string::npos : e - p - 2);
        p = e;
        size_t c = l.find(':');
        if (c == string::npos) continue;
        string k = l.substr(0, c), v = l.substr(c + 1);
        for (auto& ch : k) ch = (char)tolower((unsigned char)ch);
        while (!v.empty() && v[0] == ' ') v.erase(0, 1);
        hd[k] = v;
    }
    size_t cl = hd.count("content-length") ? (size_t)atol(hd["content-length"].c_str()) : 0;
    while (body.size() < cl && cl < (1 << 20)) {
        int n = recv(s, buf, sizeof buf, 0);
        if (n <= 0) break;
        body.append(buf, n);
    }
    size_t sp1 = line.find(' '), sp2 = line.find(' ', sp1 + 1);
    if (sp1 == string::npos || sp2 == string::npos) { closesocket(s); return; }
    string method = line.substr(0, sp1), target = line.substr(sp1 + 1, sp2 - sp1 - 1);
    string path = target, query;
    size_t qm = target.find('?');
    if (qm != string::npos) { path = target.substr(0, qm); query = target.substr(qm + 1); }

    // защита от DNS-rebinding: допускаем только свой адрес
    string host = hd["host"];
    string h1 = "127.0.0.1:" + std::to_string(g_port), h2 = "localhost:" + std::to_string(g_port);
    if (host != h1 && host != h2) { reply(s, 403, "text/plain; charset=utf-8", "forbidden"); closesocket(s); return; }

    const char* JSON = "application/json; charset=utf-8";
    if (path == "/" && method == "GET") {
        reply(s, 200, "text/html; charset=utf-8", readUi());
    } else if (path == "/favicon.ico") {
        reply(s, 204, "image/x-icon", "");
    } else if (path == "/api/ping") {
        reply(s, 200, JSON, string("{\"admin\":") + (isElevated() ? "true" : "false") + "}");
    } else if (path.rfind("/api/", 0) == 0) {
        if (hd["x-token"] != g_token) { reply(s, 403, JSON, "{\"ok\":false,\"error\":\"bad token\"}"); closesocket(s); return; }
        auto q = parseQuery(query);
        if (path == "/api/info" && method == "GET") {
            wchar_t un[256] = L"", cn[256] = L""; DWORD n1 = 256, n2 = 256;
            GetUserNameW(un, &n1); GetComputerNameW(cn, &n2);
            reply(s, 200, JSON, string("{\"admin\":") + (isElevated() ? "true" : "false") + ",\"user\":" + jstr(un) +
                                    ",\"host\":" + jstr(cn) + ",\"quarantine\":" + jstr(g_exeDir + L"\\Quarantine") +
                                    ",\"version\":\"" + APP_VERSION + "\"}");
        } else if (path == "/api/update" && method == "GET") {
            reply(s, 200, JSON, updateJson());
        } else if (path == "/api/scan" && method == "GET") {
            string cat = q["cat"];
            bool known = false;
            for (auto c : CAT_IDS) if (cat == c) known = true;
            if (!known) reply(s, 400, JSON, "{\"ok\":false,\"error\":\"unknown cat\"}");
            else reply(s, 200, JSON, scanJson(cat, toWide(q["path"])));
        } else if (path == "/api/remove" && method == "POST") {
            auto b = parseQuery(body);
            reply(s, 200, JSON, removeJson(b["ids"], b["mode"]));
        } else if (path == "/api/reveal" && method == "POST") {
            reply(s, 200, JSON, revealJson(atol(q["id"].c_str())));
        } else if (path == "/api/settings" && method == "GET") {
            reply(s, 200, JSON, settingsJson());
        } else if (path == "/api/settings" && method == "POST") {
            auto b = parseQuery(body);
            {
                std::lock_guard<std::mutex> lc(g_cfgMx);
                if (b.count("whitelist")) g_wlOn = b["whitelist"] == "1";
                if (b.count("defender")) g_defOn = b["defender"] == "1";
                if (b.count("updates")) g_updOff = b["updates"] != "1";
                saveSettings();
            }
            reply(s, 200, JSON, settingsJson());
        } else if (path == "/api/trust" && method == "POST") {
            auto b = parseQuery(body);
            reply(s, 200, JSON, trustJson(b["ids"], true, ""));
        } else if (path == "/api/untrust" && method == "POST") {
            auto b = parseQuery(body);
            reply(s, 200, JSON, trustJson(b["ids"], false, b["key"]));
        } else if (path == "/api/ack" && method == "POST") {
            auto b = parseQuery(body);
            reply(s, 200, JSON, ackJson(b["ids"], b["on"] != "0"));
        } else if (path == "/api/undo" && method == "POST") {
            auto b = parseQuery(body);
            reply(s, 200, JSON, undoJson(b["token"]));
        } else if (path == "/api/quarantine" && method == "GET") {
            reply(s, 200, JSON, quarantineListJson());
        } else if (path == "/api/quarantine/act" && method == "POST") {
            auto b = parseQuery(body);
            reply(s, 200, JSON, quarantineActJson(b["file"], b["op"]));
        } else if (path == "/api/hosts/change" && method == "POST") {
            auto b = parseQuery(body);
            reply(s, 200, JSON, hostsChangeJson(b["op"], b["old"], b["ip"], b["names"]));
        } else if (path == "/api/journal" && method == "GET") {
            reply(s, 200, JSON, journalJson());
        } else if (path == "/api/defender/prefs" && method == "GET") {
            reply(s, 200, JSON, defPrefsJson());
        } else if (path == "/api/defender/change" && method == "POST") {
            auto b = parseQuery(body);
            reply(s, 200, JSON, defChangeJson(b["kind"], b["op"], toWide(b["value"])));
        } else if (path == "/api/defscan" && method == "POST") {
            reply(s, 200, JSON, defScanJson(atol(q["id"].c_str())));
        } else if (path == "/api/elevate" && method == "POST") {
            if (isElevated()) { reply(s, 200, JSON, "{\"ok\":false,\"error\":\"уже запущено от администратора\"}"); }
            else {
                wstring params = L"--no-open --port " + std::to_wstring(g_port);
                HINSTANCE r = ShellExecuteW(nullptr, L"runas", g_selfExe.c_str(), params.c_str(), nullptr, SW_SHOWNORMAL);
                if ((INT_PTR)r > 32) {
                    reply(s, 200, JSON, "{\"ok\":true}");
                    closesocket(s);
                    Sleep(700);
                    ExitProcess(0);
                } else reply(s, 200, JSON, "{\"ok\":false,\"error\":\"запрос прав отменён\"}");
            }
        } else if (path == "/api/shutdown" && method == "POST") {
            reply(s, 200, JSON, "{\"ok\":true}");
            closesocket(s);
            Sleep(200);
            ExitProcess(0);
        } else reply(s, 404, JSON, "{\"ok\":false,\"error\":\"not found\"}");
    } else reply(s, 404, "text/plain; charset=utf-8", "not found");
    shutdown(s, SD_SEND);
    closesocket(s);
}

// ============================================================ запуск
static int runWeb(int argc, char** argv) {
    bool noOpen = false; int reqPort = 0;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--no-open")) noOpen = true;
        else if (!strcmp(argv[i], "--port") && i + 1 < argc) reqPort = atoi(argv[++i]);
    }
    wchar_t me[MAX_PATH * 2];
    GetModuleFileNameW(nullptr, me, MAX_PATH * 2);
    g_selfExe = me;
    g_exeDir = fs::path(me).parent_path().wstring();
    wchar_t wb[MAX_PATH]; GetWindowsDirectoryW(wb, MAX_PATH);
    g_winOrig = wb; g_win = lowerW(wb);
    loadCfg();
    jlog("start", "Сканер запущен");

    std::random_device rd;
    char tk[40];
    snprintf(tk, sizeof tk, "%08x%08x%08x", rd(), rd(), rd());
    g_token = tk;

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa)) { puts("WSAStartup failed"); return 1; }
    SOCKET ls = INVALID_SOCKET;
    int first = reqPort ? reqPort : 8787;
    int tries = reqPort ? 100 : 30;   // с --port ждём освобождения порта (до ~10 с)
    for (int i = 0; i < tries && ls == INVALID_SOCKET; i++) {
        int port = reqPort ? reqPort : first + i;
        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        BOOL ex = TRUE;
        setsockopt(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (char*)&ex, sizeof ex);
        sockaddr_in a{}; a.sin_family = AF_INET; a.sin_port = htons((u_short)port);
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (bind(s, (sockaddr*)&a, sizeof a) == 0 && listen(s, 64) == 0) { ls = s; g_port = port; }
        else { closesocket(s); if (reqPort) Sleep(100); }
    }
    if (ls == INVALID_SOCKET) { puts("Не удалось занять локальный порт."); return 1; }

    string url = "http://127.0.0.1:" + std::to_string(g_port) + "/";
    printf("\n  Сканер системы запущен\n  Адрес: %s\n  Права администратора: %s\n  Закрой это окно, чтобы остановить сканер.\n\n",
           url.c_str(), isElevated() ? "да" : "нет");
    if (!noOpen) ShellExecuteW(nullptr, L"open", toWide(url).c_str(), nullptr, nullptr, SW_SHOWNORMAL);

    for (;;) {
        SOCKET c = accept(ls, nullptr, nullptr);
        if (c == INVALID_SOCKET) continue;
        std::thread(handleClient, c).detach();
    }
    return 0;
}
