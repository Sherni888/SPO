// language: C++/WDK, file: driver.cpp, target: Windows 11 x64 kernel mode
// SPO kernel driver — disk serial spoof + SMBIOS UUID patch
//
// Build: WDK 11 (wdk-build 10.0.26100.x), MSVC 17.x
// Loading: requires kdmapper OR EV-signed cert

#include <ntddk.h>
#include <wdm.h>
#include <ntstrsafe.h>

#define POOL_TAG            'opSX'
#define MAX_DISKS           8

#define IOCTL_STORAGE_QUERY_PROPERTY \
    CTL_CODE(IOCTL_STORAGE_BASE, 0x0500, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_ATA_PASS_THROUGH \
    CTL_CODE(IOCTL_SCSI_BASE, 0x040B, METHOD_BUFFERED, FILE_READ_WRITE_DATA)

#define IOCTL_ATA_PASS_THROUGH_DIRECT \
    CTL_CODE(IOCTL_SCSI_BASE, 0x040C, METHOD_NEITHER, FILE_READ_WRITE_DATA)

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

#pragma pack(push, 1)
typedef struct _STORAGE_DEVICE_DESCRIPTOR {
    ULONG   Version;
    ULONG   Size;
    UCHAR   DeviceType;
    UCHAR   DeviceTypeModifier;
    BOOLEAN RemovableMedia;
    BOOLEAN CommandQueueing;
    ULONG   VendorIdOffset;
    ULONG   ProductIdOffset;
    ULONG   ProductRevisionOffset;
    ULONG   SerialNumberOffset;
    ULONG   BusType;
    ULONG   RawPropertiesLength;
    UCHAR   RawDeviceProperties[1];
} STORAGE_DEVICE_DESCRIPTOR, *PSTORAGE_DEVICE_DESCRIPTOR;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct _ATA_PASS_THROUGH_EX {
    USHORT Length;
    USHORT AtaFlags;
    UCHAR  PathId;
    UCHAR  TargetId;
    UCHAR  Lun;
    UCHAR  ReservedAsUchar;
    ULONG  DataTransferLength;
    ULONG  TimeOutValue;
    ULONG  ReservedAsUlong;
    LARGE_INTEGER DataBufferOffset;
    UCHAR  PreviousTaskFile[8];
    UCHAR  CurrentTaskFile[8];
} ATA_PASS_THROUGH_EX, *PATA_PASS_THROUGH_EX;

typedef struct _ATA_IDENTIFY_DEVICE_DATA {
    USHORT Reserved1[10];
    CHAR   SerialNumber[20];
    USHORT Reserved2[3];
    CHAR   FirmwareRevision[8];
    CHAR   ModelNumber[40];
} ATA_IDENTIFY_DEVICE_DATA, *PATA_IDENTIFY_DEVICE_DATA;
#pragma pack(pop)

typedef struct _DISK_FILTER_CTX {
    PDEVICE_OBJECT LowerDevice;
    CHAR           SpoofedSerial[24];
    BOOL           Active;
} DISK_FILTER_CTX, *PDISK_FILTER_CTX;

static DISK_FILTER_CTX g_Disks[MAX_DISKS];
static LONG            g_DiskCount = 0;

static ULONG g_Seed = 0;

static VOID SeedRng(VOID) {
    LARGE_INTEGER t;
    KeQuerySystemTime(&t);
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

static NTSTATUS OnIoCompletion(PDEVICE_OBJECT DevObj, PIRP Irp, PVOID Context) {
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

        if (code == IOCTL_ATA_PASS_THROUGH || code == IOCTL_ATA_PASS_THROUGH_DIRECT) {
            if (outLen >= sizeof(ATA_PASS_THROUGH_EX) + 512) {
                PATA_IDENTIFY_DEVICE_DATA id =
                    (PATA_IDENTIFY_DEVICE_DATA)(outBuf + sizeof(ATA_PASS_THROUGH_EX));
                CHAR ata[21];
                MakeAtaSerial(ata, 21);
                RtlCopyMemory(id->SerialNumber, ata, 20);
            }
        }
    }

done:
    if (Irp->PendingReturned) IoMarkIrpPending(Irp);
    return STATUS_CONTINUE_COMPLETION;
}

static NTSTATUS DispatchDeviceControl(PDEVICE_OBJECT DevObj, PIRP Irp) {
    PDISK_FILTER_CTX ctx = (PDISK_FILTER_CTX)DevObj->DeviceExtension;
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;

    if (code == IOCTL_STORAGE_QUERY_PROPERTY ||
        code == IOCTL_ATA_PASS_THROUGH        ||
        code == IOCTL_ATA_PASS_THROUGH_DIRECT) {
        IoCopyCurrentIrpStackLocationToNext(Irp);
        IoSetCompletionRoutine(Irp, OnIoCompletion, ctx, TRUE, TRUE, TRUE);
        return IoCallDriver(ctx->LowerDevice, Irp);
    }

    IoSkipCurrentIrpStackLocation(Irp);
    return IoCallDriver(ctx->LowerDevice, Irp);
}

static NTSTATUS DispatchPassthrough(PDEVICE_OBJECT DevObj, PIRP Irp) {
    PDISK_FILTER_CTX ctx = (PDISK_FILTER_CTX)DevObj->DeviceExtension;
    IoSkipCurrentIrpStackLocation(Irp);
    return IoCallDriver(ctx->LowerDevice, Irp);
}

static UCHAR SmBiosChecksum(PUCHAR buf, SIZE_T len) {
    UCHAR sum = 0;
    for (SIZE_T i = 0; i < len; i++) sum += buf[i];
    return sum;
}
UNREFERENCED_PARAMETER(SmBiosChecksum);

static VOID PatchSmbios(VOID) {
    const PHYSICAL_ADDRESS phyStart = { 0xF0000, 0 };
    const SIZE_T           scanSize  = 0x10000;

    PVOID mapped = MmMapIoSpace(phyStart, scanSize, MmNonCached);
    if (!mapped) {
        KdPrint(("[spo] SMBIOS scan: MmMapIoSpace failed\n"));
        return;
    }

    PSMBIOS_ENTRY_POINT_21 ep = NULL;
    for (SIZE_T off = 0; off + sizeof(SMBIOS_ENTRY_POINT_21) < scanSize; off += 16) {
        PUCHAR p = (PUCHAR)mapped + off;
        if (p[0] == '_' && p[1] == 'S' && p[2] == 'M' && p[3] == '_') {
            ep = (PSMBIOS_ENTRY_POINT_21)p;
            break;
        }
    }

    if (!ep) {
        KdPrint(("[spo] SMBIOS entry point not found\n"));
        MmUnmapIoSpace(mapped, scanSize);
        return;
    }

    PHYSICAL_ADDRESS tablePhys;
    tablePhys.QuadPart = ep->StructureTableAddress;
    PVOID table = MmMapIoSpace(tablePhys, ep->StructureTableLength + 8, MmNonCached);
    if (!table) { MmUnmapIoSpace(mapped, scanSize); return; }

    PUCHAR cur = (PUCHAR)table;
    PUCHAR end = cur + ep->StructureTableLength;
    BOOL patchedType1 = FALSE, patchedType2 = FALSE;

    while (cur < end) {
        PSMBIOS_HEADER hdr = (PSMBIOS_HEADER)cur;
        if (hdr->Type == 127) break;

        if (hdr->Type == 1 && hdr->Length >= sizeof(SMBIOS_TYPE1) && !patchedType1) {
            PSMBIOS_TYPE1 t1 = (PSMBIOS_TYPE1)cur;
            for (int i = 0; i < 16; i++) {
                if (i == 6)      t1->UUID[i] = (t1->UUID[i] & 0xF0) | (RandByteK() & 0x0F);
                else if (i == 8) t1->UUID[i] = (t1->UUID[i] & 0x3F) | 0x80;
                else             t1->UUID[i] = RandByteK();
            }
            patchedType1 = TRUE;
            KdPrint(("[spo] SMBIOS Type1 UUID patched\n"));
        }

        if (hdr->Type == 2 && hdr->Length >= sizeof(SMBIOS_TYPE2) && !patchedType2) {
            PSMBIOS_TYPE2 t2 = (PSMBIOS_TYPE2)cur;
            PCHAR strTable = (PCHAR)(cur + hdr->Length);
            PCHAR strEnd   = (PCHAR)end;
            PCHAR s = strTable;
            int   idx = 1;
            while (idx < t2->SerialNumber && s < strEnd) {
                while (*s && s < strEnd) s++;
                s++;
                idx++;
            }
            if (s < strEnd && *s) {
                SIZE_T origLen = strnlen(s, (SIZE_T)(strEnd - s));
                if (origLen > 0) {
                    CHAR newSerial[24] = { 0 };
                    MakeSerial(newSerial, min(origLen + 1, sizeof(newSerial)));
                    RtlCopyMemory(s, newSerial, origLen);
                    patchedType2 = TRUE;
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

    MmUnmapIoSpace(table, ep->StructureTableLength + 8);
    MmUnmapIoSpace(mapped, scanSize);
}

static NTSTATUS AttachDiskFilter(PDRIVER_OBJECT DriverObject, ULONG diskIdx) {
    if (diskIdx >= MAX_DISKS || g_DiskCount >= MAX_DISKS)
        return STATUS_INSUFFICIENT_RESOURCES;

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
    status = IoCreateDevice(DriverObject, sizeof(DISK_FILTER_CTX), NULL,
        FILE_DEVICE_DISK, FILE_DEVICE_SECURE_OPEN, FALSE, &filterDev);
    if (!NT_SUCCESS(status)) { ObDereferenceObject(fileObj); return status; }

    LONG idx = InterlockedIncrement(&g_DiskCount) - 1;
    PDISK_FILTER_CTX ctx = (PDISK_FILTER_CTX)filterDev->DeviceExtension;
    ctx->LowerDevice = IoAttachDeviceToDeviceStack(filterDev, targetDev);
    if (!ctx->LowerDevice) {
        IoDeleteDevice(filterDev);
        ObDereferenceObject(fileObj);
        return STATUS_UNSUCCESSFUL;
    }

    MakeSerial(ctx->SpoofedSerial, sizeof(ctx->SpoofedSerial));
    ctx->Active = TRUE;
    g_Disks[idx] = *ctx;

    filterDev->Flags |= DO_BUFFERED_IO;
    filterDev->Flags &= ~DO_DEVICE_INITIALIZING;
    ObDereferenceObject(fileObj);
    KdPrint(("[spo] filter attached: Harddisk%lu -> serial '%s'\n",
        diskIdx, ctx->SpoofedSerial));
    return STATUS_SUCCESS;
}

EXTERN_C NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject,
                               PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    SeedRng();
    RtlZeroMemory(g_Disks, sizeof(g_Disks));

    for (int i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
        DriverObject->MajorFunction[i] = DispatchPassthrough;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchDeviceControl;

    int attached = 0;
    for (ULONG i = 0; i < MAX_DISKS; i++)
        if (NT_SUCCESS(AttachDiskFilter(DriverObject, i))) attached++;
    KdPrint(("[spo] disk filters: %d attached\n", attached));

    PatchSmbios();
    KdPrint(("[spo] driver loaded OK\n"));
    return STATUS_SUCCESS;
}
