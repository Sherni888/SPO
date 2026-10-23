#pragma once
// language: C++20, file: backup.hpp, target: Windows 11 x64, MSVC
// save originals before spoofing, restore on demand

#include <string>
#include <vector>
#include <optional>
#include <fstream>
#include <filesystem>

struct BackupEntry {
    std::wstring key;   // logical name, e.g. L"MachineGuid"
    std::wstring value; // original string value
};

class Backup {
public:
    explicit Backup(std::wstring path) : m_path(std::move(path)) {}

    void Add(const std::wstring& key, const std::wstring& value);
    bool Save() const;
    bool Load();
    std::optional<std::wstring> Get(const std::wstring& key) const;
    bool HasEntries() const { return !m_entries.empty(); }

private:
    std::wstring              m_path;
    std::vector<BackupEntry>  m_entries;
};

bool RestoreFromBackup(const std::wstring& backupPath);
