// language: C++20, file: spoof_gpu.cpp, target: Windows 11 x64, MSVC
// GPU registry fingerprint spoofing

#include "spoof_gpu.hpp"
#include "utils.hpp"

static constexpr wchar_t k_VideoBase[] =
    L"SYSTEM\\CurrentControlSet\\Control\\Video";

static std::wstring RandomDriverVersion() {
    std::uniform_int_distribution<int> minor(0, 99);
    std::uniform_int_distribution<int> build(4000, 5500);
    return std::format(L"31.0.{}.{}", minor(Rng()), build(Rng()));
}

GpuSpoofResult SpoofGpuIdentifiers(Backup& bk) {
    GpuSpoofResult res{};

    auto videoGuids = RegEnumSubkeys(HKEY_LOCAL_MACHINE, k_VideoBase);
    for (const auto& guid : videoGuids) {
        if (guid[0] != L'{') continue;
        std::wstring guidPath = std::wstring(k_VideoBase) + L"\\" + guid;
        auto subNums = RegEnumSubkeys(HKEY_LOCAL_MACHINE, guidPath.c_str());

        for (const auto& num : subNums) {
            if (!iswdigit(num[0])) continue;
            std::wstring fullPath = guidPath + L"\\" + num;

            std::wstring drvName;
            if (!RegReadString(HKEY_LOCAL_MACHINE, fullPath.c_str(),
                    L"InstalledDisplayDrivers", drvName))
                continue;

            std::wstring origVer;
            RegReadString(HKEY_LOCAL_MACHINE, fullPath.c_str(),
                L"DriverVersion", origVer);
            bk.Add(L"GPU_DrvVer_" + guid + num, origVer);

            auto newVer = RandomDriverVersion();
            RegWriteString(HKEY_LOCAL_MACHINE, fullPath.c_str(),
                L"DriverVersion", newVer);

            LOGOK(L"GPU DriverVer   -> %s", newVer.c_str());
            ++res.adaptersPatched;
        }
    }

    static constexpr wchar_t k_DisplayClass[] =
        L"SYSTEM\\CurrentControlSet\\Control\\Class\\"
        L"{4D36E968-E325-11CE-BFC1-08002BE10318}";

    auto dispSubs = RegEnumSubkeys(HKEY_LOCAL_MACHINE, k_DisplayClass);
    for (const auto& sub : dispSubs) {
        if (!iswdigit(sub[0])) continue;
        std::wstring path = std::wstring(k_DisplayClass) + L"\\" + sub;

        std::wstring desc;
        if (!RegReadString(HKEY_LOCAL_MACHINE, path.c_str(),
                L"DriverDesc", desc)) continue;

        if (desc.find(L"Microsoft") != std::wstring::npos &&
            desc.find(L"Basic") != std::wstring::npos) continue;

        std::uniform_int_distribution<int> year(2022, 2024);
        std::uniform_int_distribution<int> month(1, 12);
        std::uniform_int_distribution<int> day(1, 28);
        auto drvDate = std::format(L"{:02d}-{:02d}-{}",
            month(Rng()), day(Rng()), year(Rng()));
        RegWriteString(HKEY_LOCAL_MACHINE, path.c_str(), L"DriverDate", drvDate);
        RegWriteString(HKEY_LOCAL_MACHINE, path.c_str(), L"DriverVersion",
            RandomDriverVersion());

        LOGOK(L"GPU Class %-4s   -> %s, date %s",
            sub.c_str(), desc.c_str(), drvDate.c_str());
    }

    RegWriteString(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\NVIDIA Corporation\\Logging",
        L"UniqueId", RandomGuid());
    RegWriteString(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\AMD\\CN",
        L"DeviceId", RandomGuid());

    if (res.adaptersPatched == 0)
        LOGW(L"No GPU adapters found in Video class key");

    return res;
}
