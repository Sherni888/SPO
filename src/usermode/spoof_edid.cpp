// language: C++20, file: spoof_edid.cpp, target: Windows 11 x64, MSVC
// Patch monitor EDID serial number descriptor in registry

#include "spoof_edid.hpp"
#include "utils.hpp"

static constexpr wchar_t k_DisplayBase[] =
    L"SYSTEM\\CurrentControlSet\\Enum\\DISPLAY";

static void FixEdidChecksum(uint8_t* edid, size_t sz) {
    if (sz < 128) return;
    uint8_t sum = 0;
    for (size_t i = 0; i < 127; i++) sum += edid[i];
    edid[127] = static_cast<uint8_t>((256 - sum) & 0xFF);
}

static void PatchEdidDescriptors(uint8_t* edid, size_t sz) {
    if (sz < 128) return;

    for (int i = 8; i < 12; i++) edid[i] = RandByte();

    for (int d = 0; d < 4; d++) {
        size_t off = 0x36 + static_cast<size_t>(d) * 18;
        if (off + 18 > sz) break;
        if (edid[off] != 0 || edid[off + 1] != 0 || edid[off + 2] != 0) continue;

        uint8_t dtype = edid[off + 3];
        if (dtype == 0xFF) {
            uint8_t* data = edid + off + 5;
            bool written = false;
            for (int c = 0; c < 13; c++) {
                if (data[c] == 0x0A) { written = true; break; }
                uint8_t ch = 0x30 + (RandByte() % 36);
                if (ch > 0x39) ch += 7;
                data[c] = ch;
            }
            if (!written) data[12] = 0x0A;
        } else if (dtype == 0xFC) {
            uint8_t* data = edid + off + 5;
            static const char chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            for (int c = 0; c < 3; c++)
                data[c] = chars[RandByte() % 26];
            data[3] = 0x20;
            for (int c = 4; c < 12; c++)
                data[c] = (c < 10) ? (0x30 + RandByte() % 10) : 0x20;
            data[12] = 0x0A;
        }
    }

    FixEdidChecksum(edid, sz);
}

EdidSpoofResult SpoofMonitorEdid(Backup& bk) {
    EdidSpoofResult res{};

    auto monitorIds = RegEnumSubkeys(HKEY_LOCAL_MACHINE, k_DisplayBase);
    for (const auto& monId : monitorIds) {
        std::wstring monPath = std::wstring(k_DisplayBase) + L"\\" + monId;
        auto instances = RegEnumSubkeys(HKEY_LOCAL_MACHINE, monPath.c_str());

        for (const auto& inst : instances) {
            std::wstring paramPath = monPath + L"\\" + inst + L"\\Device Parameters";

            std::vector<uint8_t> edid;
            if (!RegReadBinary(HKEY_LOCAL_MACHINE, paramPath.c_str(),
                    L"EDID", edid) || edid.size() < 128)
                continue;

            std::wstring hexOrig;
            hexOrig.reserve(edid.size() * 2);
            for (uint8_t b : edid) hexOrig += std::format(L"{:02X}", b);
            bk.Add(L"EDID_" + monId + L"_" + inst, hexOrig);

            PatchEdidDescriptors(edid.data(), edid.size());

            if (RegWriteBinary(HKEY_LOCAL_MACHINE, paramPath.c_str(),
                    L"EDID", edid.data(), static_cast<DWORD>(edid.size()))) {
                LOGOK(L"EDID patched    -> %s\\%s", monId.c_str(), inst.c_str());
                ++res.monitorsPatched;
            } else {
                LOGF(L"EDID write failed for %s\\%s", monId.c_str(), inst.c_str());
            }

            std::wstring overridePath = monPath + L"\\" + inst + L"\\EDID_OVERRIDE";
            std::vector<uint8_t> ov;
            if (RegReadBinary(HKEY_LOCAL_MACHINE, overridePath.c_str(), L"0", ov)
                && ov.size() >= 128) {
                PatchEdidDescriptors(ov.data(), ov.size());
                RegWriteBinary(HKEY_LOCAL_MACHINE, overridePath.c_str(),
                    L"0", ov.data(), static_cast<DWORD>(ov.size()));
            }
        }
    }

    if (res.monitorsPatched == 0)
        LOGW(L"No EDID entries found — monitor may not have EDID in registry");

    return res;
}
