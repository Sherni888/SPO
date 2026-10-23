// language: C++20, file: backup.cpp, target: Windows 11 x64, MSVC

#include "backup.hpp"
#include "utils.hpp"
#include <fstream>
#include <sstream>
#include <codecvt>
#include <locale>

// simple line format: KEY=VALUE (hex-encoded to survive newlines/special chars)

static std::wstring HexEncode(const std::wstring& s) {
    std::wstring out;
    out.reserve(s.size() * 4);
    for (wchar_t c : s)
        out += std::format(L"{:04X}", static_cast<uint32_t>(c));
    return out;
}

static std::wstring HexDecode(const std::wstring& s) {
    std::wstring out;
    out.reserve(s.size() / 4);
    for (size_t i = 0; i + 3 < s.size(); i += 4) {
        wchar_t ch = static_cast<wchar_t>(std::stoul(
            std::wstring(s.begin() + i, s.begin() + i + 4), nullptr, 16));
        out += ch;
    }
    return out;
}

void Backup::Add(const std::wstring& key, const std::wstring& value) {
    for (auto& e : m_entries) {
        if (e.key == key) return;  // first write wins
    }
    m_entries.push_back({ key, value });
}

bool Backup::Save() const {
    std::wofstream f(m_path, std::ios::trunc);
    if (!f) return false;
    f.imbue(std::locale(f.getloc(), new std::codecvt_utf8<wchar_t>));
    f << L"# SPO backup v1\n";
    for (const auto& e : m_entries)
        f << HexEncode(e.key) << L"=" << HexEncode(e.value) << L"\n";
    return f.good();
}

bool Backup::Load() {
    std::wifstream f(m_path);
    if (!f) return false;
    f.imbue(std::locale(f.getloc(), new std::codecvt_utf8<wchar_t>));
    m_entries.clear();
    std::wstring line;
    while (std::getline(f, line)) {
        if (line.empty() || line[0] == L'#') continue;
        auto eq = line.find(L'=');
        if (eq == std::wstring::npos) continue;
        m_entries.push_back({
            HexDecode(line.substr(0, eq)),
            HexDecode(line.substr(eq + 1))
        });
    }
    return !m_entries.empty();
}

std::optional<std::wstring> Backup::Get(const std::wstring& key) const {
    for (const auto& e : m_entries)
        if (e.key == key) return e.value;
    return std::nullopt;
}

// ── restore driver ────────────────────────────────────────────────────────────

bool RestoreFromBackup(const std::wstring& backupPath) {
    Backup bk(backupPath);
    if (!bk.Load()) {
        LOGF(L"Backup file not found or empty: %s", backupPath.c_str());
        return false;
    }

    bool all = true;

    auto Restore = [&](const wchar_t* logName, const wchar_t* regName,
                       HKEY root, const wchar_t* path, const wchar_t* valName) {
        auto orig = bk.Get(regName);
        if (!orig) { LOGW(L"%s not in backup", logName); return; }
        if (RegWriteString(root, path, valName, *orig))
            LOGOK(L"%s restored -> %s", logName, orig->c_str());
        else { LOGF(L"%s restore failed", logName); all = false; }
    };

    Restore(L"MachineGuid",   L"MachineGuid",
        HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Cryptography", L"MachineGuid");

    Restore(L"HwProfileGuid", L"HwProfileGuid",
        HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\IDConfigDB\\Hardware Profiles\\0001",
        L"HwProfileGuid");

    Restore(L"ComputerName",  L"ComputerName",
        HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerName",
        L"ComputerName");

    // NIC MACs — stored as NIC_0000, NIC_0001, ...
    const wchar_t* nicBase =
        L"SYSTEM\\CurrentControlSet\\Control\\Class\\"
        L"{4D36E972-E325-11CE-BFC1-08002BE10318}";
    auto subs = RegEnumSubkeys(HKEY_LOCAL_MACHINE, nicBase);
    for (const auto& sub : subs) {
        if (!iswdigit(sub[0])) continue;
        std::wstring bkKey = L"NIC_" + sub;
        auto orig = bk.Get(bkKey);
        if (!orig) continue;
        std::wstring path = std::wstring(nicBase) + L"\\" + sub;
        if (RegWriteString(HKEY_LOCAL_MACHINE, path.c_str(), L"NetworkAddress", *orig))
            LOGOK(L"NIC %s MAC restored", sub.c_str());
    }

    LOGI(L"Restore complete. Reboot to apply.");
    return all;
}
