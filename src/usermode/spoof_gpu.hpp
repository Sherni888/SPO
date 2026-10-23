#pragma once
// language: C++20, file: spoof_gpu.hpp

#include "backup.hpp"

struct GpuSpoofResult {
    int adaptersPatched;
};

GpuSpoofResult SpoofGpuIdentifiers(Backup& bk);
