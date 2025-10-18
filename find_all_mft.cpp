
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

using namespace std;

#pragma pack(push, 1)


struct NTFS_BOOT_SECTOR {
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
    signed char ClustersPerMFTRecord; // can be negative
    BYTE Reserved5[3];
    BYTE ClustersPerIndexBuffer;
    BYTE Reserved6[3];
    ULONGLONG VolumeSerialNumber;
    DWORD Checksum;
    BYTE BootCode[426];
    WORD EndMarker;
};


struct MFT_ENTRY_HEADER {
    DWORD Signature; // 'FILE'
    WORD UpdateSequenceOffset;
    WORD UpdateSequenceSize;
    ULONGLONG LSN;
    WORD SequenceNumber;
    WORD HardLinkCount;
    WORD FirstAttributeOffset;
    WORD Flags;
    DWORD UsedSize;
    DWORD AllocatedSize;
    ULONGLONG FileReference;
    WORD NextAttributeID;
    WORD Reserved;
    DWORD MFTRecordNumber;
};

struct ATTRIBUTE_HEADER {
    DWORD Type;
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
    BYTE Flags;
    BYTE Reserved;
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


struct Run {
    ULONGLONG vcn_start; 
    ULONGLONG length;
    LONGLONG lcn_start;  
};
vector<Run> g_MFT_Runs;


string WideToUtf8(const WCHAR* wstr, int len) {
    if (len <= 0) return string();
    std::wstring ws(wstr, wstr + len);
    std::wstring_convert<std::codecvt_utf8<wchar_t>> conv;
    return conv.to_bytes(ws);
}


ULONGLONG GetMFTRecordSizeFromClusters(signed char clustersPerRecord, ULONGLONG bytesPerSector, ULONGLONG sectorsPerCluster) {
    if (clustersPerRecord < 0) {
        int power = -clustersPerRecord;
        return 1ULL << power; 
    }
    else {
        return (ULONGLONG)clustersPerRecord * sectorsPerCluster * bytesPerSector;
    }
}


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


bool ReadFromDrive(HANDLE hDisk, ULONGLONG lba, BYTE* buffer, ULONGLONG byteCount) {
    LARGE_INTEGER offset;
    offset.QuadPart = (LONGLONG)(lba * g_BytesPerSector);
    if (!SetFilePointerEx(hDisk, offset, NULL, FILE_BEGIN)) return false;

    DWORD toRead = (DWORD)byteCount;
    DWORD bytesRead = 0;
    if (!ReadFile(hDisk, buffer, toRead, &bytesRead, NULL)) return false;
    return ((ULONGLONG)bytesRead == byteCount);
}

// Read boot sector
bool ReadBootSector(HANDLE hDisk, ULONGLONG startLBA, NTFS_BOOT_SECTOR& outBoot) {
    BYTE buf[512];
    if (!ReadFromDrive(hDisk, startLBA, buf, 512)) return false;
    memcpy(&outBoot, buf, sizeof(NTFS_BOOT_SECTOR));
    return true;
}


vector<Run> ParseDataRuns(const BYTE* runlist, SIZE_T maxLen) {
    vector<Run> runs;
    SIZE_T idx = 0;
    ULONGLONG vcn_cursor = 0;
    LONGLONG prev_lcn = 0;

    while (idx < maxLen) {
        BYTE header = runlist[idx];
        idx++;
        if (header == 0x00) break; 

        int lengthSize = header & 0x0F;
        int offsetSize = (header >> 4) & 0x0F;
        if (lengthSize == 0 || (idx + lengthSize + offsetSize) > maxLen) {
            break;
        }

     
        ULONGLONG length = 0;
        for (int i = 0; i < lengthSize; i++) {
            length |= ((ULONGLONG)runlist[idx + i]) << (8 * i);
        }
        idx += lengthSize;

       
        LONGLONG offset = 0;
      
        if (offsetSize > 0) {
       
            offset = 0;
            for (int i = 0; i < offsetSize; i++) {
                offset |= ((LONGLONG)runlist[idx + i]) << (8 * i);
            }
        
            LONGLONG sign_bit = 1LL << (offsetSize * 8 - 1);
            if (offset & sign_bit) {
                LONGLONG mask = ((1LL << (offsetSize * 8)) - 1);
                offset = offset | (~mask);
            }
        }
        idx += offsetSize;

        LONGLONG lcn_start = prev_lcn + offset;
        Run r;
        r.vcn_start = vcn_cursor;
        r.length = length;
        r.lcn_start = lcn_start;
        runs.push_back(r);

        vcn_cursor += length;
        prev_lcn = lcn_start;
    }

    return runs;
}


MFTEntryInfo ParseMFTEntry(const BYTE* mft_entry, ULONGLONG record_size) {
    MFTEntryInfo info;
    info.valid = false;
    info.parent_entry = 0;
    info.file_size = 0;
    info.is_directory = false;

    if (record_size < sizeof(MFT_ENTRY_HEADER)) return info;
    const MFT_ENTRY_HEADER* hdr = (const MFT_ENTRY_HEADER*)mft_entry;
    if (hdr->Signature != 0x454C4946) return info; // 'FILE'
    info.is_directory = (hdr->Flags & 0x02) != 0;

    WORD attrOffset = hdr->FirstAttributeOffset;
    if (attrOffset == 0 || attrOffset >= record_size) return info;

    while (attrOffset + sizeof(ATTRIBUTE_HEADER) < record_size) {
        const ATTRIBUTE_HEADER* attr = (const ATTRIBUTE_HEADER*)(mft_entry + attrOffset);
        if (attr->Length == 0) break;
        if (attr->Type == 0xFFFFFFFF) break;

        if (attr->Type == 0x30 && attr->NonResident == 0) {
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


bool ReadMFTEntryUsingRunlist(HANDLE hDisk, ULONGLONG entry_number, BYTE* outBuf, ULONGLONG record_size) {
 
    ULONGLONG byteOffset = entry_number * record_size;
    
    ULONGLONG clusterIndex = byteOffset / g_ClusterSize;
    ULONGLONG offsetWithinCluster = byteOffset % g_ClusterSize;


    for (size_t i = 0; i < g_MFT_Runs.size(); i++) {
        Run& r = g_MFT_Runs[i];
        if (clusterIndex >= r.vcn_start && clusterIndex < r.vcn_start + r.length) {
        
            ULONGLONG insideRunIndex = clusterIndex - r.vcn_start;
            LONGLONG targetLCN = r.lcn_start + (LONGLONG)insideRunIndex;
            if (targetLCN < 0) return false; 
            ULONGLONG physicalLBA = (ULONGLONG)targetLCN * g_SectorsPerCluster + g_CDriveStartLBA;
      
            ULONGLONG bytesToCover = offsetWithinCluster + record_size;
            ULONGLONG clustersToRead = (bytesToCover + g_ClusterSize - 1) / g_ClusterSize;
            ULONGLONG bytesToRead = clustersToRead * g_ClusterSize;

            vector<BYTE> temp;
            temp.resize((size_t)bytesToRead);
   
            ULONGLONG readLBA = (ULONGLONG)targetLCN * g_SectorsPerCluster + g_CDriveStartLBA;
            ULONGLONG readBytes = bytesToRead;
            if (!ReadFromDrive(hDisk, readLBA, temp.data(), readBytes)) {
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

    ULONGLONG mft_start_lba = (ULONGLONG)g_MFT_LCN * g_SectorsPerCluster + g_CDriveStartLBA;

    ULONGLONG bytesToRead = max(record_size, g_ClusterSize);
    ULONGLONG clustersToRead = (bytesToRead + g_ClusterSize - 1) / g_ClusterSize;
    ULONGLONG readBytes = clustersToRead * g_ClusterSize;

    vector<BYTE> rec;
    rec.resize((size_t)readBytes);

    if (!ReadFromDrive(hDisk, (ULONGLONG)g_MFT_LCN * g_SectorsPerCluster + g_CDriveStartLBA, rec.data(), readBytes)) {

        if (!ReadFromDrive(hDisk, (ULONGLONG)g_MFT_LCN * g_SectorsPerCluster + g_CDriveStartLBA, rec.data(), g_ClusterSize)) {
            return false;
        }
    }


    vector<BYTE> recRecord((size_t)record_size);
    memset(recRecord.data(), 0, (size_t)record_size);
    memcpy(recRecord.data(), rec.data(), min((size_t)readBytes, (size_t)record_size));


    if (!ApplyFixupToMFTRecord(recRecord.data(), (SIZE_T)record_size)) {

    }

    const MFT_ENTRY_HEADER* hdr = (const MFT_ENTRY_HEADER*)recRecord.data();
    if (hdr->Signature != 0x454C4946) return false;

    WORD offset = hdr->FirstAttributeOffset;
    SIZE_T rec_size_t = (SIZE_T)record_size;
    while (offset + sizeof(ATTRIBUTE_HEADER) < rec_size_t) {
        const ATTRIBUTE_HEADER* attr = (const ATTRIBUTE_HEADER*)(recRecord.data() + offset);
        if (attr->Length == 0) break;
        if (attr->Type == 0xFFFFFFFF) break;

        if (attr->Type == 0x80 && attr->NonResident != 0) {
            const NONRESIDENT_ATTRIBUTE* nonres = (const NONRESIDENT_ATTRIBUTE*)(recRecord.data() + offset + sizeof(ATTRIBUTE_HEADER));
            WORD runlistOffset = nonres->RunListOffset;
            if (runlistOffset == 0) return false;
            const BYTE* runlistPtr = recRecord.data() + offset + runlistOffset;
            SIZE_T maxLen = attr->Length - runlistOffset;
            vector<Run> runs = ParseDataRuns(runlistPtr, maxLen);
            if (runs.empty()) return false;
            g_MFT_Runs = runs;
            return true;
        }

        offset += attr->Length;
    }

    return false;
}


int main(int argc, char* argv[]) {
    printf("===============================================\n");
    printf("  MFT Dumper (with runlist parsing for fragmented MFT)\n");
    printf("===============================================\n\n");

    if (argc < 2) {
        printf("Usage: %s <C_drive_start_LBA>\n", argv[0]);
        return 1;
    }

    g_CDriveStartLBA = strtoull(argv[1], NULL, 10);
    if (g_CDriveStartLBA == 0) {
        printf("[ERROR] Invalid LBA value\n");
        return 1;
    }

    printf("[Step 1] Opening \\\\.\\PhysicalDrive0 ...\n");
    HANDLE hDisk = CreateFileA("\\\\.\\PhysicalDrive0",
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        0,
        NULL);

    if (hDisk == INVALID_HANDLE_VALUE) {
        printf("[ERROR] Failed to open PhysicalDrive0. Run as Administrator.\n");
        return 1;
    }
    printf("[OK] Opened\n");

    // read boot sector
    NTFS_BOOT_SECTOR boot;
    if (!ReadBootSector(hDisk, g_CDriveStartLBA, boot)) {
        printf("[ERROR] Could not read NTFS boot sector\n");
        CloseHandle(hDisk);
        return 1;
    }

    if (strncmp((char*)boot.OemName, "NTFS    ", 8) != 0) {
        printf("[ERROR] Not NTFS (OEM: %.8s)\n", boot.OemName);
        CloseHandle(hDisk);
        return 1;
    }

    g_BytesPerSector = boot.BytesPerSector;
    g_SectorsPerCluster = boot.SectorsPerCluster;
    g_ClusterSize = g_BytesPerSector * g_SectorsPerCluster;
    g_MFT_LCN = boot.MFT_LCN;

    ULONGLONG mft_record_size = GetMFTRecordSizeFromClusters(boot.ClustersPerMFTRecord, g_BytesPerSector, g_SectorsPerCluster);

    printf("[Step 2] NTFS detected\n");
    printf("  Bytes Per Sector: %llu\n", g_BytesPerSector);
    printf("  Sectors Per Cluster: %llu\n", g_SectorsPerCluster);
    printf("  Cluster Size: %llu bytes\n", g_ClusterSize);
    printf("  MFT LCN: %llu\n", g_MFT_LCN);
    printf("  MFT Record Size: %llu bytes\n\n", mft_record_size);

    // Build runlist
    printf("[Step 3] Building $MFT runlist from entry 0...\n");
    if (!BuildMFTRunlistFromEntry0(hDisk, mft_record_size)) {
        printf("[WARN] Could not build runlist from entry 0 using simple read.\n");
        printf("       The $MFT might be in an unexpected layout or fixup failed.\n");
        printf("       Trying fallback: assume contiguous MFT (previous method)...\n");
       
        Run r;
        r.vcn_start = 0;
        r.length = 0xFFFFFFFFFFFFFFFFULL; 
        r.lcn_start = (LONGLONG)g_MFT_LCN;
        g_MFT_Runs.clear();
        g_MFT_Runs.push_back(r);
    }
    else {
        printf("[OK] Runlist parsed. Runs found: %zu\n", g_MFT_Runs.size());
        for (size_t i = 0; i < g_MFT_Runs.size(); i++) {
            printf("  Run %zu: VCN=%llu, LEN=%llu clusters, LCN=%lld\n",
                i, g_MFT_Runs[i].vcn_start, g_MFT_Runs[i].length, g_MFT_Runs[i].lcn_start);
        }
    }


    printf("[Step 4] Scanning MFT entries via runlist mapping...\n");
    const int MAX_ENTRIES = 2500000;
    int found = 0;
    vector<BYTE> recBuf((size_t)mft_record_size);

    for (int i = 0; i < MAX_ENTRIES; i++) {
        bool ok = ReadMFTEntryUsingRunlist(hDisk, (ULONGLONG)i, recBuf.data(), mft_record_size);
        if (!ok) {
       
            if (i > 100 && (i % 1000) == 0) {

            }
  
            continue;
        }

        MFTEntryInfo info = ParseMFTEntry(recBuf.data(), mft_record_size);
        if (info.valid) {
            string fullpath = ReconstructPath(hDisk, (ULONGLONG)i, mft_record_size);
            const char* t = info.is_directory ? "DIR" : "FILE";
            printf("[%d] %s (%s) | Size: %llu | Path: %s\n", i, info.filename.c_str(), t, info.file_size, fullpath.c_str());
            found++;
            if (_stricmp(info.filename.c_str(), "SAM") == 0 ||
                _stricmp(info.filename.c_str(), "SYSTEM") == 0 ||
                _stricmp(info.filename.c_str(), "SECURITY") == 0) {
                printf("[INFO] Found candidate sensitive file: %s (MFT entry %d) Path: %s\n", info.filename.c_str(), i, fullpath.c_str());
      
            }
        }

        if (i % 10000 == 0 && i > 0) {
            fprintf(stderr, "  [Progress] Scanned index %d, found %d valid\n", i, found);
        }
    }

    printf("\n[Complete] Total valid entries found: %d\n", found);
    printf("If you still don't see SAM/SYSTEM/SECURITY, consider:\n");
    printf(" - The files may be in NTFS-protected $Secure area (EFS / registry hives moved) or stored as extents.\n");
    printf(" - Use a raw-forensic tool like 'icat'/'ntfsinfo' to verify layout.\n");

    CloseHandle(hDisk);
    return 0;
}
