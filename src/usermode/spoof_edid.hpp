#pragma once
// language: C++20, file: spoof_edid.hpp

#include "backup.hpp"

struct EdidSpoofResult {
    int monitorsPatched;
};

EdidSpoofResult SpoofMonitorEdid(Backup& bk);
