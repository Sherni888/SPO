// language: C++/WDK, file: driver.cpp, target: Windows 11 x64 kernel mode
// SPO kernel driver — disk serial spoof + SMBIOS UUID patch

#include <ntddk.h>
#include <wdm.h>
#include <ntstrsafe.h>
#include <ntddscsi.h>
#include <ntddstor.h>

// ── UEFI SMBIOS firmware table class (ntddk.h defines the struct; just the enum value) ──
#define SystemFirmwareTableInformation 76u

// ZwQuerySystemInformation is in ntifs.h, not ntddk.h — declare manually with ULONG class param
EXTERN_C NTSTATUS ZwQuerySystemInformation(ULONG SystemInformationClass,
    PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);

// ── constants ─────────────────────────────────────────────────────────────────

#define POOL_TAG            'opSX'
#define MAX_DISKS           8

// ── SMBIOS structures ─────────────────────────────────────────────────────────

#pragma pack(push, 1)
typedef struct _SMBIOS_ENTRY_POINT_21 {
    CHAR   Signature[4];
    UINT8  Checksum;
    UINT8  Length;
    UINT8  MajorVersion;
    UINT8  MinorVersion;
    UINT16 MaxStructureSize;
    UINT8  EntryPointRevision;
    UINT8  FormattedArea[5];
    CHAR   IntermediateAnchor[5];
    UINT8  IntermediateChecksum;
    UINT16 StructureTableLength;
    UINT32 StructureTableAddress;
    UINT16 NumberOfStructures;
    UINT8  BcdRevision;
} SMBIOS_ENTRY_POINT_21, *PSMBIOS_ENTRY_POINT_21;

typedef struct _SMBIOS_HEADER {
    UINT8  Type;
    UINT8  Length;
    UINT16 Handle;
} SMBIOS_HEADER, *PSMBIOS_HEADER;

typedef struct _SMBIOS_TYPE1 {
    SMBIOS_HEADER  Header;
    UINT8          Manufacturer;
    UINT8          ProductName;
    UINT8          Version;
    UINT8          SerialNumber;
    UINT8          UUID[16];
    UINT8          WakeUpType;
    UINT8          SKUNumber;
    UINT8          Family;
} SMBIOS_TYPE1, *PSMBIOS_TYPE1;

typedef struct _SMBIOS_TYPE2 {
    SMBIOS_HEADER  Header;
    UINT8          Manufacturer;
    UINT8          Product;
    UINT8          Version;
    UINT8          SerialNumber;
    UINT8          AssetTag;
    UINT8          FeatureFlags;
    UINT8          LocationInChassis;
    UINT16         ChassisHandle;
    UINT8          BoardType;
    UINT8          NumberOfContainedObjectHandles;
} SMBIOS_TYPE2, *PSMBIOS_TYPE2;
#pragma pack(pop)

// ── ATA IDENTIFY passthrough layout ──────────────────────────────────────────

#pragma pack(push, 1)
typedef struct _ATA_IDENTIFY_DEVICE_DATA {
    USHORT Reserved1[10];
    CHAR   SerialNumber[20];
    USHORT Reserved2[3];
    CHAR   FirmwareRevision[8];
    CHAR   ModelNumber[40];
    USHORT Reserved3[13];
} ATA_IDENTIFY_DEVICE_DATA, *PATA_IDENTIFY_DEVICE_DATA;
#pragma pack(pop)

// ── per-disk filter context ───────────────────────────────────────────────────

typedef struct _DISK_FILTER_CTX {
    PDEVICE_OBJECT FilterDevice;
    PDEVICE_OBJECT LowerDevice;
    CHAR           SpoofedSerial[24];
    CHAR           SpoofedSerialAta[20];
    BOOLEAN        Active;
} DISK_FILTER_CTX, *PDISK_FILTER_CTX;

static DISK_FILTER_CTX g_Disks[MAX_DISKS];
static LONG            g_DiskCount = 0;

// ── PRNG (xorshift32 — kernel safe, no FPU) ───────────────────────────────────

static ULONG g_Seed = 0;

static VOID SeedRng(VOID) {
    LARGE_INTEGER t;
    KeQuerySystemTimePrecise(&t);
    g_Seed = (ULONG)(t.QuadPart ^ (t.QuadPart >> 32));
    if (g_Seed == 0) g_Seed = 0xBAADF00D;
}

static ULONG RandU32K(VOID) {
    g_Seed ^= g_Seed << 13;
    g_Seed ^= g_Seed >> 17;
    g_Seed ^= g_Seed << 5;
    return g_Seed;
}

static UCHAR RandByteK(VOID) { return (UCHAR)(RandU32K() & 0xFF); }

static VOID MakeSerial(PCHAR buf, SIZE_T len) {
    static const CHAR table[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    SIZE_T i;
    for (i = 0; i < len - 1; i++)
        buf[i] = table[RandByteK() % 36];
    buf[len - 1] = '\0';
}

static VOID MakeAtaSerial(PCHAR buf, SIZE_T len) {
    CHAR tmp[21] = { 0 };
    SIZE_T fill = len > 20 ? 20 : len;
    MakeSerial(tmp, fill + 1);
    for (SIZE_T i = 0; i + 1 < fill; i += 2) {
        buf[i]     = tmp[i + 1];
        buf[i + 1] = tmp[i];
    }
    if (fill & 1) buf[fill - 1] = ' ';
    for (SIZE_T i = fill; i < 20; i++) buf[i] = ' ';
}

// ── patch STORAGE_DEVICE_DESCRIPTOR serial ────────────────────────────────────

static VOID PatchStorageDescriptor(PUCHAR buf, ULONG bufLen,
                                   PDISK_FILTER_CTX ctx) {
    if (bufLen < sizeof(STORAGE_DEVICE_DESCRIPTOR)) return;
    PSTORAGE_DEVICE_DESCRIPTOR desc = (PSTORAGE_DEVICE_DESCRIPTOR)buf;
    if (desc->SerialNumberOffset == 0) return;
    if (desc->SerialNumberOffset >= bufLen) return;

    PCHAR serial = (PCHAR)(buf + desc->SerialNumberOffset);
    ULONG maxLen = bufLen - desc->SerialNumberOffset;

    SIZE_T copyLen = min(maxLen - 1, (ULONG)(sizeof(ctx->SpoofedSerial) - 1));
    RtlCopyMemory(serial, ctx->SpoofedSerial, copyLen);
    serial[copyLen] = '\0';
}

// ── IRP completion routine ────────────────────────────────────────────────────

static NTSTATUS OnIoCompletion(PDEVICE_OBJECT DevObj,
                               PIRP Irp, PVOID Context) {
    UNREFERENCED_PARAMETER(DevObj);
    PDISK_FILTER_CTX ctx = (PDISK_FILTER_CTX)Context;

    if (!ctx || !ctx->Active) goto done;
    if (!NT_SUCCESS(Irp->IoStatus.Status)) goto done;

    {
        PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
        ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;
        PUCHAR outBuf = (PUCHAR)Irp->AssociatedIrp.SystemBuffer;
        ULONG  outLen = stack->Parameters.DeviceIoControl.OutputBufferLength;

        if (!outBuf) goto done;

        if (code == IOCTL_STORAGE_QUERY_PROPERTY)
            PatchStorageDescriptor(outBuf, outLen, ctx);

        if (code == IOCTL_ATA_PASS_THROUGH) {
            if (outLen >= sizeof(ATA_PASS_THROUGH_EX) + 512) {
                PATA_PASS_THROUGH_EX apt = (PATA_PASS_THROUGH_EX)outBuf;
                LONGLONG dbo = (LONGLONG)apt->DataBufferOffset;
                if (dbo >= (LONGLONG)sizeof(ATA_PASS_THROUGH_EX) &&
                    dbo + 512 <= (LONGLONG)outLen) {
                    PATA_IDENTIFY_DEVICE_DATA id =
                        (PATA_IDENTIFY_DEVICE_DATA)(outBuf + dbo);
                    RtlCopyMemory(id->SerialNumber, ctx->SpoofedSerialAta, 20);
                }
            }
        }

        if (code == IOCTL_SCSI_PASS_THROUGH &&
            outLen > sizeof(SCSI_PASS_THROUGH)) {
            PSCSI_PASS_THROUGH spt = (PSCSI_PASS_THROUGH)outBuf;
            if (spt->CdbLength >= 4      &&
                spt->Cdb[0]  == 0x12     &&
                (spt->Cdb[1] & 0x01)     &&
                spt->Cdb[2]  == 0x80     &&
                spt->DataBufferOffset > 0 &&
                spt->DataTransferLength  >= 5)
            {
                ULONG_PTR dbo = (ULONG_PTR)spt->DataBufferOffset;
                if (dbo + 4 < outLen) {
                    PUCHAR data   = outBuf + dbo;
                    ULONG  pgLen  = data[3];
                    ULONG  avail  = (ULONG)(outLen - dbo - 4);
                    if (pgLen > 0 && pgLen <= avail && pgLen < 24) {
                        ULONG copyLen = min(pgLen,
                            (ULONG)(sizeof(ctx->SpoofedSerial) - 1));
                        RtlCopyMemory(data + 4, ctx->SpoofedSerial, copyLen);
                    }
                }
            }
        }
    }

done:
    if (Irp->PendingReturned) IoMarkIrpPending(Irp);
    return STATUS_CONTINUE_COMPLETION;
}

// ── dispatch: DeviceControl ───────────────────────────────────────────────────

static NTSTATUS DispatchDeviceControl(PDEVICE_OBJECT DevObj, PIRP Irp) {
    PDISK_FILTER_CTX ctx = (PDISK_FILTER_CTX)DevObj->DeviceExtension;
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;

    if (code == IOCTL_STORAGE_QUERY_PROPERTY ||
        code == IOCTL_ATA_PASS_THROUGH        ||
        code == IOCTL_SCSI_PASS_THROUGH) {
        IoCopyCurrentIrpStackLocationToNext(Irp);
        IoSetCompletionRoutine(Irp, OnIoCompletion, ctx, TRUE, TRUE, TRUE);
        return IoCallDriver(ctx->LowerDevice, Irp);
    }

    IoSkipCurrentIrpStackLocation(Irp);
    return IoCallDriver(ctx->LowerDevice, Irp);
}

// ── dispatch: passthrough ─────────────────────────────────────────────────────

static NTSTATUS DispatchPassthrough(PDEVICE_OBJECT DevObj, PIRP Irp) {
    PDISK_FILTER_CTX ctx = (PDISK_FILTER_CTX)DevObj->DeviceExtension;
    IoSkipCurrentIrpStackLocation(Irp);
    return IoCallDriver(ctx->LowerDevice, Irp);
}

// ── SMBIOS patch ──────────────────────────────────────────────────────────────

static BOOLEAN PatchSmbiosStructures(PUCHAR buf, ULONG len) {
    PUCHAR cur = buf;
    PUCHAR end = buf + len;
    BOOLEAN p1 = FALSE, p2 = FALSE;

    while (cur + sizeof(SMBIOS_HEADER) < end) {
        PSMBIOS_HEADER hdr = (PSMBIOS_HEADER)cur;
        if (hdr->Type == 127) break;

        if (hdr->Type == 1 && hdr->Length >= sizeof(SMBIOS_TYPE1) && !p1) {
            PSMBIOS_TYPE1 t1 = (PSMBIOS_TYPE1)cur;
            for (int i = 0; i < 16; i++) {
                if      (i == 6) t1->UUID[i] = (t1->UUID[i] & 0xF0) | (RandByteK() & 0x0F);
                else if (i == 8) t1->UUID[i] = (t1->UUID[i] & 0x3F) | 0x80;
                else             t1->UUID[i] = RandByteK();
            }
            p1 = TRUE;
            KdPrint(("[spo] SMBIOS Type1 UUID patched\n"));
        }

        if (hdr->Type == 2 && hdr->Length >= sizeof(SMBIOS_TYPE2) && !p2) {
            PSMBIOS_TYPE2 t2    = (PSMBIOS_TYPE2)cur;
            PCHAR         strTbl = (PCHAR)(cur + hdr->Length);
            PCHAR         strEnd = (PCHAR)end;
            PCHAR         s     = strTbl;
            int           idx   = 1;
            while (idx < t2->SerialNumber && s < strEnd) {
                while (*s && s < strEnd) s++;
                s++; idx++;
            }
            if (s < strEnd && *s) {
                SIZE_T origLen = 0;
                while (origLen < (SIZE_T)(strEnd - s) && s[origLen]) origLen++;
                if (origLen > 0) {
                    CHAR newSer[24] = { 0 };
                    MakeSerial(newSer, min(origLen + 1, sizeof(newSer)));
                    RtlCopyMemory(s, newSer, origLen);
                    p2 = TRUE;
                    KdPrint(("[spo] SMBIOS Type2 baseboard serial patched\n"));
                }
            }
        }

        cur += hdr->Length;
        while (cur + 1 < end) {
            if (cur[0] == 0 && cur[1] == 0) { cur += 2; break; }
            while (*cur && cur < end) cur++;
            cur++;
        }
    }
    return (p1 || p2);
}

static BOOLEAN PatchSmbios(VOID) {
    const PHYSICAL_ADDRESS phyStart = { 0xF0000, 0 };
    const SIZE_T           scanSize  = 0x10000;

    PVOID mapped = MmMapIoSpace(phyStart, scanSize, MmNonCached);
    if (!mapped) { KdPrint(("[spo] SMBIOS legacy: MmMapIoSpace failed\n")); return FALSE; }

    PSMBIOS_ENTRY_POINT_21 ep = NULL;
    for (SIZE_T off = 0; off + sizeof(SMBIOS_ENTRY_POINT_21) < scanSize; off += 16) {
        PUCHAR p = (PUCHAR)mapped + off;
        if (p[0] == '_' && p[1] == 'S' && p[2] == 'M' && p[3] == '_') {
            ep = (PSMBIOS_ENTRY_POINT_21)p; break;
        }
    }
    if (!ep) {
        KdPrint(("[spo] SMBIOS legacy: entry point not found\n"));
        MmUnmapIoSpace(mapped, scanSize);
        return FALSE;
    }

    PHYSICAL_ADDRESS tblPhys;
    tblPhys.QuadPart = ep->StructureTableAddress;
    ULONG tblLen = ep->StructureTableLength;
    MmUnmapIoSpace(mapped, scanSize);

    PVOID table = MmMapIoSpace(tblPhys, tblLen + 8, MmNonCached);
    if (!table) { KdPrint(("[spo] SMBIOS legacy: table map failed\n")); return FALSE; }

    BOOLEAN ok = PatchSmbiosStructures((PUCHAR)table, tblLen);
    MmUnmapIoSpace(table, tblLen + 8);
    if (ok) KdPrint(("[spo] SMBIOS legacy: OK\n"));
    return ok;
}

static VOID PatchSmbiosUefi(VOID) {
    const ULONG initSz = sizeof(SYSTEM_FIRMWARE_TABLE_INFORMATION) + 0x8000;
    PSYSTEM_FIRMWARE_TABLE_INFORMATION sfti =
        (PSYSTEM_FIRMWARE_TABLE_INFORMATION)ExAllocatePoolWithTag(
            NonPagedPool, initSz, POOL_TAG);
    if (!sfti) return;

    sfti->ProviderSignature = 'RSMB';
    sfti->Action            = SystemFirmwareTable_Get;
    sfti->TableID           = 0;
    sfti->TableBufferLength = initSz -
        FIELD_OFFSET(SYSTEM_FIRMWARE_TABLE_INFORMATION, TableBuffer);

    ULONG    needed = 0;
    NTSTATUS st = ZwQuerySystemInformation(
        SystemFirmwareTableInformation,
        sfti, initSz, &needed);

    if (st == STATUS_BUFFER_TOO_SMALL && needed) {
        ExFreePoolWithTag(sfti, POOL_TAG);
        sfti = (PSYSTEM_FIRMWARE_TABLE_INFORMATION)ExAllocatePoolWithTag(
            NonPagedPool, needed, POOL_TAG);
        if (!sfti) return;
        sfti->ProviderSignature = 'RSMB';
        sfti->Action            = SystemFirmwareTable_Get;
        sfti->TableID           = 0;
        sfti->TableBufferLength = needed -
            FIELD_OFFSET(SYSTEM_FIRMWARE_TABLE_INFORMATION, TableBuffer);
        st = ZwQuerySystemInformation(
            SystemFirmwareTableInformation,
            sfti, needed, &needed);
    }

    if (!NT_SUCCESS(st) || sfti->TableBufferLength < 9) {
        KdPrint(("[spo] ZwQSI RSMB: 0x%X\n", st));
        ExFreePoolWithTag(sfti, POOL_TAG);
        return;
    }

    ULONG  smbLen  = *(ULONG*)(sfti->TableBuffer + 4);
    PUCHAR smbData = sfti->TableBuffer + 8;
    if (smbLen + 8 > sfti->TableBufferLength)
        smbLen = sfti->TableBufferLength - 8;

    UCHAR   uuid[16] = { 0 };
    BOOLEAN gotUuid  = FALSE;
    PUCHAR c = smbData, e = smbData + smbLen;
    while (c + sizeof(SMBIOS_HEADER) < e && !gotUuid) {
        PSMBIOS_HEADER h = (PSMBIOS_HEADER)c;
        if (h->Type == 127) break;
        if (h->Type == 1 && h->Length >= sizeof(SMBIOS_TYPE1)) {
            RtlCopyMemory(uuid, ((PSMBIOS_TYPE1)c)->UUID, 16);
            gotUuid = TRUE;
        }
        c += h->Length;
        while (c + 1 < e) {
            if (c[0] == 0 && c[1] == 0) { c += 2; break; }
            while (*c && c < e) c++;
            c++;
        }
    }
    ExFreePoolWithTag(sfti, POOL_TAG);

    if (!gotUuid) { KdPrint(("[spo] RSMB UEFI: no Type1\n")); return; }

    PPHYSICAL_MEMORY_RANGE ranges = MmGetPhysicalMemoryRanges();
    if (!ranges) return;

    BOOLEAN patched = FALSE;
    for (int r = 0; ranges[r].NumberOfBytes.QuadPart != 0 && !patched; r++) {
        ULONG64 base = (ULONG64)ranges[r].BaseAddress.QuadPart;
        ULONG64 span = (ULONG64)ranges[r].NumberOfBytes.QuadPart;
        if (base >= 0x100000000ULL) continue;
        if (base + span > 0x100000000ULL)
            span = 0x100000000ULL - base;

        for (ULONG64 off = 0; off < span && !patched; off += 0x10000) {
            ULONG64 chunk = min(span - off, 0x10000ULL);
            PHYSICAL_ADDRESS pa;
            pa.QuadPart = (LONGLONG)(base + off);
            PVOID m = MmMapIoSpace(pa, (SIZE_T)chunk, MmNonCached);
            if (!m) continue;

            PUCHAR p = (PUCHAR)m;
            for (SIZE_T i = 0; i + sizeof(SMBIOS_TYPE1) <= chunk && !patched; i++) {
                PSMBIOS_HEADER hdr = (PSMBIOS_HEADER)(p + i);
                if (hdr->Type == 1 && hdr->Length >= sizeof(SMBIOS_TYPE1)) {
                    PSMBIOS_TYPE1 t1 = (PSMBIOS_TYPE1)(p + i);
                    if (RtlCompareMemory(t1->UUID, uuid, 16) == 16) {
                        for (int k = 0; k < 16; k++) {
                            if      (k == 6) t1->UUID[k] = (t1->UUID[k] & 0xF0) | (RandByteK() & 0x0F);
                            else if (k == 8) t1->UUID[k] = (t1->UUID[k] & 0x3F) | 0x80;
                            else             t1->UUID[k] = RandByteK();
                        }
                        patched = TRUE;
                        KdPrint(("[spo] SMBIOS UEFI: UUID patched at phys 0x%llx\n",
                            base + off + i));
                    }
                }
            }
            MmUnmapIoSpace(m, (SIZE_T)chunk);
        }
    }
    ExFreePool(ranges);
    if (!patched) KdPrint(("[spo] SMBIOS UEFI: fingerprint not found\n"));
    else          KdPrint(("[spo] SMBIOS UEFI: OK\n"));
}

// ── attach filter to disk device ─────────────────────────────────────────────

static NTSTATUS AttachDiskFilter(PDRIVER_OBJECT DriverObject, ULONG diskIdx) {
    if (diskIdx >= MAX_DISKS) return STATUS_INSUFFICIENT_RESOURCES;
    if (g_DiskCount >= MAX_DISKS) return STATUS_INSUFFICIENT_RESOURCES;

    WCHAR nameBuf[32];
    RtlStringCchPrintfW(nameBuf, 32, L"\\Device\\Harddisk%lu\\DR0", diskIdx);
    UNICODE_STRING devName;
    RtlInitUnicodeString(&devName, nameBuf);

    PFILE_OBJECT fileObj = NULL;
    PDEVICE_OBJECT targetDev = NULL;
    NTSTATUS status = IoGetDeviceObjectPointer(&devName,
        FILE_READ_ATTRIBUTES, &fileObj, &targetDev);
    if (!NT_SUCCESS(status)) return status;

    PDEVICE_OBJECT filterDev = NULL;
    status = IoCreateDevice(DriverObject,
        sizeof(DISK_FILTER_CTX),
        NULL,
        FILE_DEVICE_DISK,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &filterDev);
    if (!NT_SUCCESS(status)) {
        ObDereferenceObject(fileObj);
        return status;
    }

    LONG idx = InterlockedIncrement(&g_DiskCount) - 1;
    PDISK_FILTER_CTX ctx = (PDISK_FILTER_CTX)filterDev->DeviceExtension;
    ctx->LowerDevice = IoAttachDeviceToDeviceStack(filterDev, targetDev);
    if (!ctx->LowerDevice) {
        IoDeleteDevice(filterDev);
        ObDereferenceObject(fileObj);
        return STATUS_UNSUCCESSFUL;
    }

    ctx->FilterDevice = filterDev;
    MakeSerial(ctx->SpoofedSerial, sizeof(ctx->SpoofedSerial));
    MakeAtaSerial(ctx->SpoofedSerialAta, sizeof(ctx->SpoofedSerialAta));
    ctx->Active = TRUE;
    g_Disks[idx] = *ctx;

    filterDev->Flags |= DO_BUFFERED_IO;
    filterDev->Flags &= ~DO_DEVICE_INITIALIZING;

    ObDereferenceObject(fileObj);
    KdPrint(("[spo] filter attached: Harddisk%lu -> serial '%s'\n",
        diskIdx, ctx->SpoofedSerial));
    return STATUS_SUCCESS;
}

// ── DriverUnload ──────────────────────────────────────────────────────────────

static VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);
    for (LONG i = 0; i < g_DiskCount; i++) {
        PDEVICE_OBJECT fdev = g_Disks[i].FilterDevice;
        if (!fdev) continue;
        PDISK_FILTER_CTX ctx = (PDISK_FILTER_CTX)fdev->DeviceExtension;
        ctx->Active = FALSE;
        if (ctx->LowerDevice) {
            IoDetachDevice(ctx->LowerDevice);
            ctx->LowerDevice = NULL;
        }
        IoDeleteDevice(fdev);
        g_Disks[i].FilterDevice = NULL;
    }
    KdPrint(("[spo] driver unloaded\n"));
}

// ── DriverEntry ───────────────────────────────────────────────────────────────

EXTERN_C NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject,
                               PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);

    SeedRng();
    RtlZeroMemory(g_Disks, sizeof(g_Disks));

    DriverObject->DriverUnload = DriverUnload;

    for (int i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
        DriverObject->MajorFunction[i] = DispatchPassthrough;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchDeviceControl;

    int attached = 0;
    for (ULONG i = 0; i < MAX_DISKS; i++) {
        if (NT_SUCCESS(AttachDiskFilter(DriverObject, i)))
            attached++;
    }
    KdPrint(("[spo] disk filters: %d attached\n", attached));

    if (!PatchSmbios())
        PatchSmbiosUefi();

    KdPrint(("[spo] driver loaded OK\n"));
    return STATUS_SUCCESS;
}
