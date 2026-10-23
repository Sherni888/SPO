#pragma once
// language: C++20, file: spoof_nic.hpp

#include "backup.hpp"

struct NicSpoofResult {
    int  devicesPatched;
    bool ndisRegistryOk;
};

NicSpoofResult SpoofNetworkAdapters(Backup& bk);
