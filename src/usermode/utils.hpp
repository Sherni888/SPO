#pragma once
// language: C++20, file: utils.hpp, target: Windows 11 x64, MSVC
// random generation, logging, registry helpers

#include <windows.h>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>
#include <random>
#include <format>
#include <span>
#include <array>

// ── RNG ──────────────────────────────────────────────────────────────────────

inline std::mt19937_64& Rng() {
    static std::mt19937_64 rng{ std::random_device{}() };
    return rng;
}

inline uint8_t  RandByte()  { return static_cast<uint8_t> (std::uniform_int_distribution<uint32_t>(0, 255)(Rng())); }
inline uint16_t RandU16()   { return static_cast<uint16_t>(std::uniform_int_distribution<uint32_t>(0, 0xFFFF)(Rng())); }
inline uint32_t RandU32()   { return static_cast<uint32_t>(std::uniform_int_distribution<uint64_t>(0, 0xFFFFFFFF)(Rng())); }
inline uint64_t RandU64()   { return std::uniform_int_distribution<uint64_t>(0, UINT64_MAX)(Rng()); }

// RFC 4122 version 4 UUID — braces included
inline std::wstring RandomGuid() {
    uint8_t b[16];
    for (auto& x : b) x = RandByte();
    b[6] = (b[6] & 0x0F) | 0x40;
    b[8] = (b[8] & 0x3F) | 0x80;
    return std::format(
        L"{{{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}"
        L"-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
        b[0],b[1],b[2],b[3], b[4],b[5], b[6],b[7],
        b[8],b[9], b[10],b[11],b[12],b[13],b[14],b[15]);
}

// locally administered unicast MAC — no braces, uppercase, no separators
inline std::wstring RandomMac() {
    uint8_t m[6];
    for (auto& x : m) x = RandByte();
    m[0] = (m[0] & 0xFE) | 0x02;
    return std::format(L"{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        m[0],m[1],m[2],m[3],m[4],m[5]);
}

// random alphanumeric string, uppercase
inline std::wstring RandomAlpha(size_t len) {
    const wchar_t c[] = L"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    std::uniform_int_distribution<int> pick(0, 35);
    std::wstring out(len, L'X');
    for (auto& ch : out) ch = c[pick(Rng())];
    return out;
}

// random serial number — OEM style: 8 hex digits + '-' + 4 + '-' + 4
inline std::wstring RandomSerial() {
    return std::format(L"{:08X}-{:04X}-{:04X}",
        RandU32(), RandU16(), RandU16());
}

// ── logging ───────────────────────────────────────────────────────────────────

enum class LogLevel { Info, Ok, Warn, Fail };

inline void Log(LogLevel lvl, const wchar_t* fmt, ...) {
    const wchar_t* tags[] = { L"[*]", L"[+]", L"[!]", L"[-]" };
    wprintf(L"%s ", tags[static_cast<int>(lvl)]);
    va_list args;
    va_start(args, fmt);
    vwprintf(fmt, args);
    va_end(args);
    wprintf(L"\n");
}

#define LOGI(...) Log(LogLevel::Info,  __VA_ARGS__)
#define LOGOK(...) Log(LogLevel::Ok,   __VA_ARGS__)
#define LOGW(...) Log(LogLevel::Warn,  __VA_ARGS__)
#define LOGF(...) Log(LogLevel::Fail,  __VA_ARGS__)

// ── registry helpers ──────────────────────────────────────────────────────────

inline bool RegReadString(HKEY root, const wchar_t* path,
                          const wchar_t* name, std::wstring& out) {
    HKEY hk = nullptr;
    if (RegOpenKeyExW(root, path, 0, KEY_QUERY_VALUE, &hk) != ERROR_SUCCESS)
        return false;
    DWORD sz = 0, type;
    if (RegQueryValueExW(hk, name, nullptr, &type, nullptr, &sz) != ERROR_SUCCESS) {
        RegCloseKey(hk); return false;
    }
    out.resize(sz / sizeof(wchar_t));
    bool ok = RegQueryValueExW(hk, name, nullptr, &type,
        reinterpret_cast<BYTE*>(out.data()), &sz) == ERROR_SUCCESS;
    RegCloseKey(hk);
    if (!out.empty() && out.back() == L'\0') out.pop_back();
    return ok;
}

inline bool RegWriteString(HKEY root, const wchar_t* path,
                           const wchar_t* name, const std::wstring& val) {
    HKEY hk = nullptr;
    DWORD disp;
    if (RegCreateKeyExW(root, path, 0, nullptr, 0,
            KEY_SET_VALUE, nullptr, &hk, &disp) != ERROR_SUCCESS)
        return false;
    bool ok = RegSetValueExW(hk, name, 0, REG_SZ,
        reinterpret_cast<const BYTE*>(val.c_str()),
        static_cast<DWORD>((val.size() + 1) * sizeof(wchar_t))) == ERROR_SUCCESS;
    RegCloseKey(hk);
    return ok;
}

inline bool RegReadDword(HKEY root, const wchar_t* path,
                         const wchar_t* name, DWORD& out) {
    HKEY hk = nullptr;
    if (RegOpenKeyExW(root, path, 0, KEY_QUERY_VALUE, &hk) != ERROR_SUCCESS)
        return false;
    DWORD sz = sizeof(DWORD), type;
    bool ok = RegQueryValueExW(hk, name, nullptr, &type,
        reinterpret_cast<BYTE*>(&out), &sz) == ERROR_SUCCESS;
    RegCloseKey(hk);
    return ok;
}

inline bool RegWriteDword(HKEY root, const wchar_t* path,
                          const wchar_t* name, DWORD val) {
    HKEY hk = nullptr;
    if (RegCreateKeyExW(root, path, 0, nullptr, 0,
            KEY_SET_VALUE, nullptr, &hk, nullptr) != ERROR_SUCCESS)
        return false;
    bool ok = RegSetValueExW(hk, name, 0, REG_DWORD,
        reinterpret_cast<const BYTE*>(&val), sizeof(DWORD)) == ERROR_SUCCESS;
    RegCloseKey(hk);
    return ok;
}

inline bool RegReadBinary(HKEY root, const wchar_t* path,
                          const wchar_t* name, std::vector<uint8_t>& out) {
    HKEY hk = nullptr;
    if (RegOpenKeyExW(root, path, 0, KEY_QUERY_VALUE, &hk) != ERROR_SUCCESS)
        return false;
    DWORD sz = 0, type;
    RegQueryValueExW(hk, name, nullptr, &type, nullptr, &sz);
    out.resize(sz);
    bool ok = RegQueryValueExW(hk, name, nullptr, &type,
        out.data(), &sz) == ERROR_SUCCESS;
    RegCloseKey(hk);
    return ok;
}

inline bool RegWriteBinary(HKEY root, const wchar_t* path,
                           const wchar_t* name,
                           const uint8_t* data, DWORD sz) {
    HKEY hk = nullptr;
    if (RegCreateKeyExW(root, path, 0, nullptr, 0,
            KEY_SET_VALUE, nullptr, &hk, nullptr) != ERROR_SUCCESS)
        return false;
    bool ok = RegSetValueExW(hk, name, 0, REG_BINARY, data, sz) == ERROR_SUCCESS;
    RegCloseKey(hk);
    return ok;
}

// enumerate immediate subkeys of a key
inline std::vector<std::wstring> RegEnumSubkeys(HKEY root, const wchar_t* path) {
    std::vector<std::wstring> keys;
    HKEY hk = nullptr;
    if (RegOpenKeyExW(root, path, 0, KEY_ENUMERATE_SUB_KEYS, &hk) != ERROR_SUCCESS)
        return keys;
    wchar_t name[256];
    DWORD idx = 0, sz;
    while (true) {
        sz = 256;
        if (RegEnumKeyExW(hk, idx++, name, &sz,
                nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) break;
        keys.emplace_back(name);
    }
    RegCloseKey(hk);
    return keys;
}

// ── elevation check ───────────────────────────────────────────────────────────

inline bool IsElevated() {
    HANDLE token = nullptr;
    TOKEN_ELEVATION elev{};
    DWORD sz = sizeof(elev);
    OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token);
    GetTokenInformation(token, TokenElevation, &elev, sz, &sz);
    CloseHandle(token);
    return elev.TokenIsElevated != 0;
}
