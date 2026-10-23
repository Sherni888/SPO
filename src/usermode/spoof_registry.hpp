#pragma once
// language: C++20, file: spoof_registry.hpp

#include "backup.hpp"

struct RegistrySpoofResult {
    bool machineGuid;
    bool hwProfileGuid;
    bool computerName;
    bool installDate;
    bool productId;
};

RegistrySpoofResult SpoofRegistryIdentifiers(Backup& bk);
