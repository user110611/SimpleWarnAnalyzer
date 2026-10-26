#include <windows.h>
#include <tlhelp32.h>
#include <filesystem>
#include <iostream>
#include <vector>
#include <string>
#include <cstdio>
#include <cwctype>
#include <ctime>

namespace fs = std::filesystem;
using std::wstring;
using std::string;
using std::vector;

static string u8(const wstring& w) {
    if (w.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    string s(n, 0);
    WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), s.data(), n, nullptr, nullptr);
    return s;
}

static wstring expand(const wstring& p) {
    wchar_t buf[MAX_PATH * 4];
    DWORD n = ExpandEnvironmentStringsW(p.c_str(), buf, MAX_PATH * 4);
    return n ? wstring(buf) : p;
}

static void title(const char* t) { printf("\n== %s ==\n", t); }

// ---------- ввод ----------
static wstring readLineW() {
    wchar_t buf[2048];
    DWORD n = 0;
    ReadConsoleW(GetStdHandle(STD_INPUT_HANDLE), buf, 2047, &n, nullptr);
    wstring s(buf, n);
    while (!s.empty() && (s.back() == L'\r' || s.back() == L'\n' || s.back() == L' '))
        s.pop_back();
    size_t start = 0;
    while (start < s.size() && s[start] == L' ') start++;
    return s.substr(start);
}

// ---------- элементы последнего списка (для rem) ----------
enum class Kind { File, Dir, RegValue, Service, Process, Task };

struct Item {
    Kind kind;
    wstring display;
    wstring path;
    wstring extra;
    HKEY root = nullptr;
    REGSAM view = 0;
    DWORD pid = 0;
};

static vector<Item> g_last;

// ---------- захват вывода в файл и показ в новом окне ----------
static wstring g_tempPath;

static void beginCapture() {
    wchar_t dir[MAX_PATH], tmp[MAX_PATH];
    GetTempPathW(MAX_PATH, dir);
    GetTempFileNameW(dir, L"av", 0, tmp);
    g_tempPath = tmp;
    _wfreopen(tmp, L"w", stdout);
}

static void showFileInNewWindow(const wstring& path, const wchar_t* extraMsg) {
    wstring cmdLine =
        L"powershell -NoExit -Command \"[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; "
        L"Get-Content -Raw -Encoding UTF8 '" + path + L"' | Write-Host\"";

    STARTUPINFOW si{}; si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    vector<wchar_t> buf(cmdLine.begin(), cmdLine.end());
    buf.push_back(0);
    if (CreateProcessW(nullptr, buf.data(), nullptr, nullptr, FALSE,
                        CREATE_NEW_CONSOLE, nullptr, nullptr, &si, &pi)) {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    } else {
        puts("  [не удалось открыть окно, смотри файл на диске]");
    }
    if (extraMsg) wprintf(extraMsg);
}

static void endCaptureAndShow() {
    fflush(stdout);
    fclose(stdout);
    freopen("CONOUT$", "w", stdout);
    showFileInNewWindow(g_tempPath, L"  результат открыт в новом окне. Для удаления используй rem прямо здесь.\n");
}

// ---------- реестр ----------
static void regList(HKEY root, const wstring& path, REGSAM view = 0) {
    g_last.clear();
    HKEY k;
    if (RegOpenKeyExW(root, path.c_str(), 0, KEY_READ | view, &k) != ERROR_SUCCESS) {
        puts("  [нет доступа или ключа нет]");
        return;
    }
    static wchar_t name[16384];
    static BYTE data[16384];
    int idx = 0;
    for (DWORD i = 0;; i++) {
        DWORD nl = 16383, dl = sizeof(data) - 2, type = 0;
        LONG r = RegEnumValueW(k, i, name, &nl, nullptr, &type, data, &dl);
        if (r == ERROR_NO_MORE_ITEMS) break;
        if (r != ERROR_SUCCESS) continue;
        data[dl] = data[dl + 1] = 0;
        idx++;
        wstring val = (type == REG_SZ || type == REG_EXPAND_SZ) ? wstring((wchar_t*)data) : L"(бинарные данные)";
        printf("[%d]  %s\n     -> %s\n", idx, u8(name).c_str(), u8(val).c_str());
        Item it; it.kind = Kind::RegValue; it.display = name; it.path = path;
        it.extra = name; it.root = root; it.view = view;
        g_last.push_back(it);
    }
    if (!idx) puts("  [пусто]");
    RegCloseKey(k);
}

// ---------- папки ----------
static void dirList(const wstring& raw) {
    g_last.clear();
    wstring p = expand(raw);
    printf("  %s\n", u8(p).c_str());
    std::error_code ec;
    if (!fs::exists(p, ec)) { puts("  [папки нет]"); return; }
    int idx = 0;
    for (fs::directory_iterator it(p, fs::directory_options::skip_permission_denied, ec), end;
         !ec && it != end; it.increment(ec)) {
        std::error_code e2;
        bool dir = it->is_directory(e2);
        unsigned long long sz = dir ? 0 : (unsigned long long)it->file_size(e2);
        DWORD at = GetFileAttributesW(it->path().c_str());
        bool hid = at != INVALID_FILE_ATTRIBUTES && (at & FILE_ATTRIBUTE_HIDDEN);
        idx++;
        printf("[%d] %c%c %10llu  %s\n", idx, dir ? 'D' : 'F', hid ? 'H' : ' ', sz,
               u8(it->path().filename().wstring()).c_str());
        Item item; item.kind = dir ? Kind::Dir : Kind::File;
        item.display = it->path().filename().wstring();
        item.path = it->path().wstring();
        g_last.push_back(item);
    }
    if (!idx) puts("  [пусто]");
}

// ---------- службы ----------
static void services() {
    g_last.clear();
    SC_HANDLE sc = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
    if (!sc) { puts("  [нужны права]"); return; }
    DWORD need = 0, cnt = 0, resume = 0;
    EnumServicesStatusExW(sc, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
                          nullptr, 0, &need, &cnt, &resume, nullptr);
    std::string buf(need + 4096, 0);
    resume = 0;
    if (!EnumServicesStatusExW(sc, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
                               (LPBYTE)buf.data(), (DWORD)buf.size(), &need, &cnt, &resume, nullptr)) {
        puts("  [ошибка чтения]"); CloseServiceHandle(sc); return;
    }
    auto* s = (ENUM_SERVICE_STATUS_PROCESSW*)buf.data();
    for (DWORD i = 0; i < cnt; i++) {
        wstring bin = L"?";
        const wchar_t* start = L"?";
        SC_HANDLE h = OpenServiceW(sc, s[i].lpServiceName, SERVICE_QUERY_CONFIG);
        if (h) {
            DWORD n = 0;
            QueryServiceConfigW(h, nullptr, 0, &n);
            std::string cb(n, 0);
            if (QueryServiceConfigW(h, (LPQUERY_SERVICE_CONFIGW)cb.data(), n, &n)) {
                auto* c = (LPQUERY_SERVICE_CONFIGW)cb.data();
                bin = c->lpBinaryPathName ? c->lpBinaryPathName : L"";
                switch (c->dwStartType) {
                    case SERVICE_AUTO_START: start = L"auto"; break;
                    case SERVICE_DEMAND_START: start = L"manual"; break;
                    case SERVICE_DISABLED: start = L"disabled"; break;
                    case SERVICE_BOOT_START: start = L"boot"; break;
                    case SERVICE_SYSTEM_START: start = L"system"; break;
                }
            }
            CloseServiceHandle(h);
        }
        bool run = s[i].ServiceStatusProcess.dwCurrentState == SERVICE_RUNNING;
        printf("[%lu] [%s] [%-8s] %s\n     -> %s\n", i + 1, run ? "run " : "stop",
               u8(start).c_str(), u8(s[i].lpServiceName).c_str(), u8(bin).c_str());
        Item item; item.kind = Kind::Service; item.display = s[i].lpServiceName;
        item.path = s[i].lpServiceName;
        g_last.push_back(item);
    }
    printf("  всего: %lu\n", cnt);
    CloseServiceHandle(sc);
}

// ---------- процессы ----------
static void processes() {
    g_last.clear();
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) { puts("  [ошибка]"); return; }
    PROCESSENTRY32W pe{}; pe.dwSize = sizeof(pe);
    int idx = 0;
    if (Process32FirstW(snap, &pe)) do {
        wstring path = L"-";
        HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
        if (h) {
            wchar_t b[MAX_PATH * 2]; DWORD n = MAX_PATH * 2;
            if (QueryFullProcessImageNameW(h, 0, b, &n)) path = b;
            CloseHandle(h);
        }
        idx++;
        printf("[%d] PID %6lu  (parent %6lu)  %-28s %s\n", idx, pe.th32ProcessID,
               pe.th32ParentProcessID, u8(pe.szExeFile).c_str(), u8(path).c_str());
        Item item; item.kind = Kind::Process; item.display = pe.szExeFile; item.pid = pe.th32ProcessID;
        g_last.push_back(item);
    } while (Process32NextW(snap, &pe));
    CloseHandle(snap);
    printf("  всего: %d\n", idx);
}

// ---------- планировщик ----------
static wstring toWide(const string& s) {
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
    wstring w(n, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), w.data(), n);
    return w;
}

static wstring firstCsvField(const string& line) {
    size_t a = line.find('"');
    if (a == string::npos) return L"";
    size_t b = line.find('"', a + 1);
    if (b == string::npos) return L"";
    return toWide(line.substr(a + 1, b - a - 1));
}

static void tasks() {
    g_last.clear();
    FILE* f = _popen("cmd /c \"chcp 65001 >nul & schtasks /query /fo csv /nh\"", "r");
    if (!f) { puts("  [ошибка]"); return; }
    char line[4096];
    int idx = 0;
    while (fgets(line, sizeof(line), f)) {
        idx++;
        printf("[%d] %s", idx, line);
        Item item; item.kind = Kind::Task;
        item.path = firstCsvField(line);
        item.display = item.path;
        g_last.push_back(item);
    }
    _pclose(f);
}

// ---------- удаление ----------
static bool deleteItem(const Item& it, string& err) {
    switch (it.kind) {
        case Kind::File: {
            std::error_code ec;
            fs::remove(it.path, ec);
            if (ec) { err = ec.message(); return false; }
            return true;
        }
        case Kind::Dir: {
            std::error_code ec;
            fs::remove_all(it.path, ec);
            if (ec) { err = ec.message(); return false; }
            return true;
        }
        case Kind::RegValue: {
            HKEY k;
            if (RegOpenKeyExW(it.root, it.path.c_str(), 0, KEY_SET_VALUE | it.view, &k) != ERROR_SUCCESS) {
                err = "нет доступа к ключу"; return false;
            }
            LONG r = RegDeleteValueW(k, it.extra.c_str());
            RegCloseKey(k);
            if (r != ERROR_SUCCESS) { err = "код ошибки " + std::to_string(r); return false; }
            return true;
        }
        case Kind::Service: {
            SC_HANDLE sc = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
            if (!sc) { err = "нужны права администратора"; return false; }
            SC_HANDLE h = OpenServiceW(sc, it.path.c_str(), DELETE | SERVICE_STOP);
            if (!h) { CloseServiceHandle(sc); err = "не удалось открыть службу"; return false; }
            SERVICE_STATUS st;
            ControlService(h, SERVICE_CONTROL_STOP, &st);
            bool ok = DeleteService(h);
            if (!ok) err = "код ошибки " + std::to_string(GetLastError());
            CloseServiceHandle(h); CloseServiceHandle(sc);
            return ok;
        }
        case Kind::Process: {
            HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, it.pid);
            if (!h) { err = "не удалось открыть процесс"; return false; }
            bool ok = TerminateProcess(h, 1);
            if (!ok) err = "код ошибки " + std::to_string(GetLastError());
            CloseHandle(h);
            return ok;
        }
        case Kind::Task: {
            string cmd = "schtasks /delete /tn \"" + u8(it.path) + "\" /f >nul 2>&1";
            int r = system(cmd.c_str());
            if (r != 0) { err = "код ошибки " + std::to_string(r); return false; }
            return true;
        }
    }
    return false;
}

static void handleRem(const wstring& args) {
    vector<int> nums;
    wstring cur;
    for (wchar_t c : args + L",") {
        if (c == L',') {
            size_t s = 0, e = cur.size();
            while (s < e && cur[s] == L' ') s++;
            while (e > s && cur[e - 1] == L' ') e--;
            wstring t = cur.substr(s, e - s);
            if (!t.empty()) {
                try { nums.push_back(std::stoi(u8(t))); } catch (...) {}
            }
            cur.clear();
        } else cur += c;
    }
    if (nums.empty()) { puts("  [не указаны номера]"); return; }

    vector<int> valid;
    puts("\n  Будут удалены:");
    for (int n : nums) {
        if (n < 1 || n > (int)g_last.size()) {
            printf("  [%d] -- нет такого номера в последнем списке\n", n);
            continue;
        }
        printf("  [%d] %s\n", n, u8(g_last[n - 1].display).c_str());
        valid.push_back(n);
    }
    if (valid.empty()) return;

    printf("\n  Подтвердить удаление? (y/n): ");
    wstring ans = readLineW();
    if (ans.empty() || std::towlower(ans[0]) != L'y') { puts("  отменено"); return; }

    for (int n : valid) {
        string err;
        bool ok = deleteItem(g_last[n - 1], err);
        if (ok) printf("  [%d] удалено\n", n);
        else printf("  [%d] ошибка: %s\n", n, err.c_str());
    }
}

// ---------- help ----------
static const char* helpText(int n) {
    switch (n) {
        case 1: return "Run (HKCU) — программы, запускающиеся при входе текущего пользователя. Самое частое место автозапуска вирусов.";
        case 2: return "Run (HKLM) — то же самое, но для всех пользователей системы. Требует прав администратора на запись.";
        case 3: return "RunOnce — программы, которые запустятся один раз и сами удалятся из списка. Используется и легитимным ПО, и вирусами.";
        case 4: return "Winlogon — ключи Userinit и Shell, которые Windows использует при входе. Подмена здесь — явный признак заражения.";
        case 5: return "Автозагрузка (пользователь) — ярлыки и программы, запускаемые Windows при входе именно этого пользователя.";
        case 6: return "Автозагрузка (все пользователи) — то же самое, но действует на любую учётную запись в системе.";
        case 7: return "Службы Windows — список служб с путём к исполняемому файлу и типом запуска. Вирусы иногда маскируются под системные службы.";
        case 8: return "Планировщик заданий — задачи по расписанию, входу или простою. Частое место закрепления скрытых угроз.";
        case 9: return "Процессы — всё, что сейчас запущено, с PID, родителем и полным путём к файлу.";
        case 10: return "AppData\\Roaming — папка, куда программы пишут без прав администратора. Частое место хранения вредоносных файлов.";
        case 11: return "AppData\\Local\\Temp — временная папка. Сюда часто скачиваются и запускаются вирусы перед закреплением.";
        case 12: return "ProgramData — общая папка данных для всех программ, тоже доступна на запись без администратора.";
        case 13: return "Своя папка — ввести любой путь вручную и посмотреть его содержимое.";
        case 14: return "Полное сканирование — прогоняет все пункты подряд и сохраняет итог в файл output_<дата>_<время>.txt.";
        default: return nullptr;
    }
}

static void handleHelp(const wstring& args) {
    wstring t = args;
    size_t s = 0, e = t.size();
    while (s < e && t[s] == L' ') s++;
    while (e > s && t[e - 1] == L' ') e--;
    t = t.substr(s, e - s);
    if (t.empty()) { puts("  использование: help <номер>"); return; }
    int n;
    try { n = std::stoi(u8(t)); } catch (...) { puts("  непонятный номер"); return; }
    const char* txt = helpText(n);
    if (!txt) { puts("  нет такого пункта"); return; }
    printf("\n  [%d] %s\n", n, txt);
}

// ---------- полное сканирование ----------
static wstring timestampName() {
    SYSTEMTIME t; GetLocalTime(&t);
    wchar_t buf[64];
    swprintf(buf, 64, L"output_%04d-%02d-%02d_%02d-%02d-%02d.txt",
             t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute, t.wSecond);
    return buf;
}

static void runFullScan() {
    wstring outName = timestampName();
    wstring outPath = fs::current_path().wstring() + L"\\" + outName;

    _wfreopen(outPath.c_str(), L"w", stdout);

    SYSTEMTIME t; GetLocalTime(&t);
    printf("ОТЧЁТ СКАНИРОВАНИЯ\n");
    printf("Дата:  %04d-%02d-%02d\n", t.wYear, t.wMonth, t.wDay);
    printf("Время: %02d:%02d:%02d\n", t.wHour, t.wMinute, t.wSecond);
    printf("========================================\n");

    title("1. Run HKCU");
    regList(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run");

    title("2. Run HKLM");
    regList(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run");

    title("3. RunOnce HKCU");
    regList(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce");

    title("4. Winlogon");
    regList(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon");

    title("5. Автозагрузка (пользователь)");
    dirList(L"%AppData%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup");

    title("6. Автозагрузка (все пользователи)");
    dirList(L"%ProgramData%\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp");

    title("7. Службы");
    services();

    title("8. Планировщик задач");
    tasks();

    title("9. Процессы");
    processes();

    title("10. AppData\\Roaming");
    dirList(L"%AppData%");

    title("11. AppData\\Local\\Temp");
    dirList(L"%TEMP%");

    title("12. ProgramData");
    dirList(L"%ProgramData%");

    printf("\n========================================\n");
    printf("конец отчёта\n");

    fflush(stdout);
    fclose(stdout);
    freopen("CONOUT$", "w", stdout);

    printf("  сохранено: %s\n", u8(outPath).c_str());
    showFileInNewWindow(outPath,
        L"  rem работает только для раздела 'Процессы' (последний в отчёте) -- для остальных открой нужный пункт меню отдельно.\n");
}

// ---------- меню ----------
static void menu() {
    puts("\n 1  Run (пользователь)");
    puts(" 2  Run (система)");
    puts(" 3  RunOnce (пользователь)");
    puts(" 4  Winlogon");
    puts(" 5  Автозагрузка: папка пользователя");
    puts(" 6  Автозагрузка: папка всех");
    puts(" 7  Службы");
    puts(" 8  Планировщик задач");
    puts(" 9  Процессы");
    puts("10  AppData\\Roaming");
    puts("11  AppData\\Local\\Temp");
    puts("12  ProgramData");
    puts("13  Своя папка");
    puts("14  Полное сканирование -> сохранить в файл (full)");
    puts(" 0  Выход");
    puts(" rem 1, 3, 5   — удалить элементы из последнего показанного списка");
    puts(" help <номер>  — объяснение, что делает пункт меню");
    printf("> ");
}

int main() {
    SetConsoleOutputCP(CP_UTF8);
    for (;;) {
        menu();
        wstring in = readLineW();
        if (in.empty()) continue;

        wstring low = in;
        for (auto& ch : low) ch = std::towlower(ch);

        if (low.rfind(L"rem", 0) == 0) {
            handleRem(in.substr(3));
            continue;
        }
        if (low.rfind(L"help", 0) == 0) {
            handleHelp(in.substr(4));
            continue;
        }
        if (low == L"full") {
            runFullScan();
            continue;
        }

        int c;
        try { c = std::stoi(u8(in)); } catch (...) { puts("  непонятная команда"); continue; }
        if (c == 0) break;
        if (c == 14) { runFullScan(); continue; }
        if (c < 1 || c > 13) { puts("  нет такого пункта"); continue; }

        beginCapture();
        switch (c) {
            case 1: title("Run HKCU");
                regList(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run"); break;
            case 2: title("Run HKLM");
                regList(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run"); break;
            case 3: title("RunOnce HKCU");
                regList(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"); break;
            case 4: title("Winlogon");
                regList(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"); break;
            case 5: title("Startup (user)");
                dirList(L"%AppData%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"); break;
            case 6: title("Startup (all users)");
                dirList(L"%ProgramData%\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp"); break;
            case 7: title("Службы"); services(); break;
            case 8: title("Планировщик"); tasks(); break;
            case 9: title("Процессы"); processes(); break;
            case 10: title("AppData Roaming"); dirList(L"%AppData%"); break;
            case 11: title("Temp"); dirList(L"%TEMP%"); break;
            case 12: title("ProgramData"); dirList(L"%ProgramData%"); break;
            case 13: {
                endCaptureAndShow();
                printf("путь: ");
                wstring p = readLineW();
                beginCapture();
                title("Папка"); dirList(p);
                break;
            }
        }
        endCaptureAndShow();
    }
    return 0;
}