#include <windows.h>
#include <shlobj.h>
#include <shlwapi.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <userenv.h>
#include <winnt.h>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <vector>
#include <thread>
#include <mutex>
#include <locale>
#include <codecvt>
#include <map>
#include <set>
#include <chrono>
#include <ctime>
#include <atomic>
#include <string>
#include <sstream>
#include <filesystem>
#include <algorithm>
#include <memory>
#include <cstdlib>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "shell32.lib")

#define LOG_FILE           "MouseFileMonitor.log"
#define STATS_FILE         "MouseFileMonitor.stats"
#define EXPORT_CSV_FILE    "MouseFileMonitor_export.csv"
#define MAX_PATH_BUFFER    4096
#define THREAD_EXPORT_FREQ 60 

std::ofstream logStream;
std::ofstream statsStream;
std::mutex logMutex;
std::mutex statsMutex;
std::mutex analysisMutex;
std::atomic<bool> programRunning(true);
std::atomic<unsigned long long> clickCount(0);
std::atomic<unsigned long long> errorCount(0);
std::set<std::wstring> filesAnalyzed;
std::mutex filesAnalyzedMutex;
std::vector<std::wstring> lastTenFiles;
std::mutex lastTenFilesMutex;
HWND explorerHwndCache = nullptr;

void getEvent(const std::string& event) {
    std::lock_guard<std::mutex> lock<logMutex>;
    auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    logStream << std::put_time(std::localtime(&now), "%F %T" ) << " [LOG] " << event << std::endl;
    logStream.flush();
}

void logError(const std::string& error) {
    std::lock_guard<std::mutex> lock(logMutex);
    auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    logStream << std::put_time(std::localtime(&now), "%F %T") << " [ERR] " << error << std::endl;
    logStream.flush();
    errorCount++;
}

std::wstring s2ws(const std::string& str) {
    std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
    return converter.from_bytes(str);
}

std::wstring s2ws(const std::string& str) {
    std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
    return converter.from_bytes(str);
}

bool fileExist(const std::wstring& path) {
    DWORD attrs = GetFileAttributesW(path.c_str());
    return (attrs != INVALID_FILE_ATTRIBUTES); 
}

std::wstring GetFileExtension(const std::wstring& filePath) {
    size_t pos = filePath.find_last_of(L".");
    if (pos == std::wstring::npos) return L"";
    return filePath.substr(pos + 1);
}

uint32_t crc32_for_byte(uint32_t r) {
    for (int j = 0; j < 8; ++j) 
        r = (r & 1? 0 : (uint32_t)0xEDB88320L) ^ r >> 1;
    
    return  r ^ (uint32_t)0xFF000000L;
}

static uint32_t table[0x100];
void InitCRC32Table() {
    for (size_t i = 0; i < 0x100; ++i) table[i] = crc32_for_byte(i);
}
uint32_t CRC32_FILE(const std::wstring& filename) {
    FILE *f = _wfopen(filename.c_str(), L"rb");
    if (!f) return 0;
    uint32_t crc = 0;
    unsigned char buf[16384];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
        for (size_t i = 0; i < n; ++i)
            crc = table[(uint8_t)crc ^ buf[i]] ^ crc >> 8;
    }
    fclose(f);
    return crc;
}

struct fileAnalisy {
    std::wstring path;
    uintmax_t size;
    std::wstring perms;
    std::wstring lastMode;
    uint32_t hash_crc32;
    std::wstring extension;
    std::wstring pr;
    std::wstring shortName;
};

std::wstring GetshrotName(const std::wstring& filepath) {
   wchar_t buffer[MAX_PATH];
   DWORD len = GetShortPathNameW(filePath.c_str(), buffer, MAX_PATH);
   if (len > 0) return std::wstring(buffer); 
   return L"";
}

std::wstring GetFilePermsStr(const std::wstring& filePath) {
    DWORD attrs = GetFileAttributesW(filePath.c_str());
    std::wstring rep = L"";
    rep += (attrs & FILE_ATTRIBUTE_READONLY)  ? L"r" : L"-";
    rep += (attrs & FILE_ATTRIBUTE_HIDDEN)    ? L"h" : L"-";
    rep += (attrs & FILE_ATTRIBUTE_SYSTEM)    ? L"s" : L"-";
    rep += (attrs & FILE_ATTRIBUTE_ARCHIVE)   ? L"a" : L"-";
    rep += (attrs & FILE_ATTRIBUTE_DIRECTORY) ? L"d" : L"-";
    return rep;
}

std::wstring GetFileOwner(const std::wstring& filePath) {
    PSID pSid = NULL;
    PSECURITY_DESCRIPTOR pSD = NULL;
    if (GetNamedSecurityInfoW(filePath.c_str(), SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION,
            &pSid, NULL, NULL, NULL, &pSD) != ERROR_SUCCESS)
        return L"unknown";

    wchar_t name[256], domain[256];
    DWORD nameSize = 256, domainSize = 256;
    SID_NAME_USE snu;
    if (LookupAccountSidW(NULL, pSid, name, &nameSize, domain, &domainSize, &snu))
        return std::wstring(domain) + L"\\" + std::wstring(name);

    if (pSD) LocalFree(pSD);
    return L"unknown";
}

std::time_t FileFT2time_t(FILETIME ft) {
    SYSTEMTIME stUTC, stLocal;
    FileTimeToSystemTime(&ft, &stUTC);
    SystemTimeToTzSpecificLocalTime(NULL, &stUTC, &stLocal);
    std::tm tm = {};
    tm.tm_year = stLocal.wYear - 1900;
    tm.tm_mon = stLocal.wMonth - 1;
    tm.tm_mday = stLocal.wDay;
    tm.tm_hour = stLocal.wHour;
    tm.tm_min = stLocal.wMinute;
    tm.tm_sec = stLocal.wSecond;
    return std::mktime(&tm);
}

bool RetrieveFileInfo(const std::wstring& filePath, FileAnalysisInfo& info) {
    try {
        WIN32_FILE_ATTRIBUTE_DATA fad;
        if (!GetFileAttributesExW(filePath.c_str(), GetFileExInfoStandard, &fad))
            return false;
        info.path = filePath;
        info.size = (((uintmax_t)fad.nFileSizeHigh) << 32) + fad.nFileSizeLow;
        info.lastMod = FileFT2time_t(fad.ftLastWriteTime);
        info.perms = GetFilePermsStr(filePath);
        info.extension = GetFileExtension(filePath);
        info.owner = GetFileOwner(filePath);
        info.shortName = GetShortName(filePath);
        info.hash_crc32 = CRC32_FILE(filePath);
        return true;
    } catch (...) {
        return false;
    }
}

void AnalyzeAndLogFile(const std::wstring& filePath) {
    std::lock_guard<std::mutex> lock(analysisMutex);
    {
        std::lock_guard<std::mutex> lock2(filesAnalyzedMutex);
        if (filesAnalyzed.find(filePath) != filesAnalyzed.end()) {
            LogEvent("[SKIP] " + ws2s(filePath) + " già analizzato");
            return;
        }
        filesAnalyzed.insert(filePath);
        lastTenFiles.push_back(filePath);
        if (lastTenFiles.size() > 10) lastTenFiles.erase(lastTenFiles.begin());
    }
    FileAnalysisInfo fi;
    if (RetrieveFileInfo(filePath, fi)) {
        std::wstringstream ws;
        ws << L"[OK] Analisi: " << fi.path
           << L" | size=" << fi.size
           << L" | owner=" << fi.owner
           << L" | perms=" << fi.perms
           << L" | ext=" << fi.extension
           << L" | short=" << fi.shortName
           << L" | hash(crc32)=" << std::hex << fi.hash_crc32;
        LogEvent(ws2s(ws.str()));
    }
    else {
        std::string err = "[FAIL] Analisi file fallita: " + ws2s(filePath);
        LogError(err);
    }
}

/****************************************************************************
 * SECTION: ESPORTAZIONE / STATISTICHE / EXPORT THREAD
 ****************************************************************************/

struct ExportStatsData {
    unsigned long long clickTot;
    unsigned long long errors;
    size_t numFiles;
    std::vector<std::wstring> lastFiles;
};
ExportStatsData GatherStats() {
    ExportStatsData d;
    d.clickTot = clickCount.load();
    d.errors = errorCount.load();
    {
        std::lock_guard<std::mutex> l(filesAnalyzedMutex);
        d.numFiles = filesAnalyzed.size();
        d.lastFiles = lastTenFiles;
    }
    return d;
}
void ExportStatsToFile() {
    ExportStatsData d = GatherStats();
    std::lock_guard<std::mutex> lock(statsMutex);
    statsStream.open(STATS_FILE, std::ios::trunc);
    if (!statsStream.is_open()) return;
    statsStream << "Clicks: " << d.clickTot << std::endl;
    statsStream << "Errors: " << d.errors << std::endl;
    statsStream << "FilesAnalyzed: " << d.numFiles << std::endl;
    statsStream << "Last 10 files:\n";
    for (auto it = d.lastFiles.rbegin(); it != d.lastFiles.rend(); ++it)
        statsStream << ws2s(*it) << std::endl;
    statsStream.close();
}
void ExportToCSV() {
    // Espandibile: Scrivi infos in formato csv (ciclando filesAnalyzed)
    std::lock_guard<std::mutex> lock(filesAnalyzedMutex);
    std::ofstream csv(EXPORT_CSV_FILE, std::ios::trunc);
    csv << "path,size,owner,perms,ext,short,hash" << std::endl;
    for (const auto& f : filesAnalyzed) {
        FileAnalysisInfo fi;
        if (!RetrieveFileInfo(f, fi)) continue;
        csv << "\"" << ws2s(fi.path) << "\","
            << fi.size << ","
            << "\"" << ws2s(fi.owner) << "\","
            << ws2s(fi.perms) << ","
            << ws2s(fi.extension) << ","
            << ws2s(fi.shortName) << ","
            << std::hex << fi.hash_crc32 << std::endl;
    }
    csv.close();
}
void ExportThread() {
    while (programRunning) {
        ExportStatsToFile();
        ExportToCSV();
        std::this_thread::sleep_for(std::chrono::seconds(THREAD_EXPORT_FREQ));
    }
}

/****************************************************************************
 * SECTION: MOUSE HOOK E CATTURA CLIC
 ****************************************************************************/

// Utilità per trovare percorso del file selezionato in Explorer tramite API COM/Automation avanzata...

// [Qui seguirebbero ~300+ linee di codice con interfacciamento UIAutomation o IShellView, 
// COM interfaces, per massima accuratezza nel trovare percorso selezionato sui click explorer]

/****************************************************************************
 * SECTION: HOOK CALLBACK
 ****************************************************************************/
LRESULT CALLBACK LowLevelMouseProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode >= 0 && (wParam == WM_LBUTTONDOWN || wParam == WM_RBUTTONDOWN)) {
        clickCount++;
        MSLLHOOKSTRUCT* mouseInfo = reinterpret_cast<MSLLHOOKSTRUCT*>(lParam);
        POINT pt = mouseInfo->pt;
        HWND hwnd = WindowFromPoint(pt);
        wchar_t windowText[256], className[256];
        GetWindowTextW(hwnd, windowText, 256);
        GetClassNameW(hwnd, className, 256);

        // Le classi Explorer sono "CabinetWClass" e simili
        if (wcscmp(className, L"CabinetWClass") == 0 || wcscmp(className, L"ExploreWClass") == 0) {
            std::wstring context = L"[CLICK] Su Explorer: ";
            context += windowText;
            LogEvent(ws2s(context));
            // Qui va la parte che interpreta la selezione di file! (TODO: sezione avanzata, oltre 200+ righe)
        }
    }
    return CallNextHookEx(NULL, nCode, wParam, lParam);
}

void MouseHookThread() {
    HHOOK mouseHook = SetWindowsHookEx(WH_MOUSE_LL, LowLevelMouseProc, NULL, 0);
    if (!mouseHook) {
        LogError("[FATAL] Hook mouse fallito.");
        return;
    }
    LogEvent("[OK] Hook mouse installato con successo.");
    MSG msg;
    while (programRunning && GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    UnhookWindowsHookEx(mouseHook);
}

/****************************************************************************
 * SECTION: MAIN PROGRAM & CLEANUP
 ****************************************************************************/

void PrintBanner() {
    std::cout << "******************************************\n";
    std::cout << "*       MouseFileMonitor by BitCrucio      *\n";
    std::cout << "*     Cattura e analizza click file       *\n";
    std::cout << "*    Logs in '" << LOG_FILE << "'         *\n";
    std::cout << "******************************************\n";
}
int main() {
    logStream.open(LOG_FILE, std::ios::app);
    if (!logStream.is_open()) {
        std::cerr << "Impossibile aprire il file di log" << std::endl;
        return 1;
    }
    InitCRC32Table();
    PrintBanner();
    LogEvent("==== MouseFileMonitor AVVIATO ====");

    std::thread mouseThread(MouseHookThread);
    std::thread exportThread(ExportThread);

    // Mini prompt loop terminale: premi 'q'+Invio per terminare
    std::string prompt;
    while (programRunning) {
        std::getline(std::cin, prompt);
        if (prompt == "q") {
            programRunning = false;
        }
        // Altro: "stats", "export", "help" ecc.
    }

    mouseThread.join();
    exportThread.join();

    ExportStatsToFile();
    ExportToCSV();

    logStream.close();
    LogEvent("==== MouseFileMonitor TERMINATO ====");
    return 0;
}
