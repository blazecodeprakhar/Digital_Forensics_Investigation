import struct
import os
import hashlib

def create_fat12_disk(filename="suspect_device.dd"):
    sector_size = 512
    total_sectors = 2880  # Standard 1.44MB floppy/USB image size (1,474,560 bytes)
    reserved_sectors = 1
    num_fats = 2
    fat_size = 9 # sectors per FAT
    root_dir_entries = 224 # 224 * 32 bytes = 14 sectors
    root_dir_sectors = (root_dir_entries * 32 + sector_size - 1) // sector_size
    data_start_sector = reserved_sectors + (num_fats * fat_size) + root_dir_sectors

    disk = bytearray(total_sectors * sector_size)

    # 1. Boot Sector (MBR / BPB)
    disk[0:3] = b"\xEB\x3C\x90" # Jump instruction
    disk[3:11] = b"MSDOS5.0"   # OEM Identifier
    struct.pack_into("<H", disk, 11, sector_size)       # Bytes per sector: 512
    disk[13] = 1                                       # Sectors per cluster: 1
    struct.pack_into("<H", disk, 14, reserved_sectors)  # Reserved sectors: 1
    disk[16] = num_fats                                # Number of FATs: 2
    struct.pack_into("<H", disk, 17, root_dir_entries)  # Root directory entries: 224
    struct.pack_into("<H", disk, 19, total_sectors)     # Total sectors: 2880
    disk[21] = 0xF0                                    # Media descriptor (removable disk)
    struct.pack_into("<H", disk, 22, fat_size)          # Sectors per FAT: 9
    struct.pack_into("<H", disk, 24, 18)                # Sectors per track: 18
    struct.pack_into("<H", disk, 26, 2)                 # Number of heads: 2
    struct.pack_into("<I", disk, 28, 0)                 # Hidden sectors: 0
    # Extended BPB
    disk[36] = 0x00                                    # Drive number: 0x00
    disk[37] = 0x00                                    # Reserved
    disk[38] = 0x29                                    # Extended boot signature
    struct.pack_into("<I", disk, 39, 0x12345678)        # Volume serial number
    disk[43:54] = b"SUSPECT_USB"                       # Volume label (11 chars)
    disk[54:62] = b"FAT12   "                          # File system type (8 chars)
    # Boot signature at sector end
    disk[510] = 0x55
    disk[511] = 0xAA

    # 2. File Allocation Tables (FAT1 and FAT2)
    # FAT[0] = 0xFF0, FAT[1] = 0xFFF
    fat1_offset = reserved_sectors * sector_size
    fat2_offset = (reserved_sectors + fat_size) * sector_size

    def set_fat12_entry(fat_bytes, entry_idx, val):
        offset = (entry_idx * 3) // 2
        if entry_idx % 2 == 0:
            fat_bytes[offset] = val & 0xFF
            fat_bytes[offset + 1] = (fat_bytes[offset + 1] & 0xF0) | ((val >> 8) & 0x0F)
        else:
            fat_bytes[offset] = (fat_bytes[offset] & 0x0F) | ((val << 4) & 0xF0)
            fat_bytes[offset + 1] = (val >> 4) & 0xFF

    fat_table = bytearray(fat_size * sector_size)
    fat_table[0] = 0xF0
    fat_table[1] = 0xFF
    fat_table[2] = 0xFF

    # Data payloads
    policy_content = b"%PDF-1.4\n1 0 obj\n<< /Title (Corporate Security Policy 2026) /Author (InfoSec Dept) >>\nendobj\n2 0 obj\n<< /Type /Catalog /Pages 3 0 R >>\nendobj\nxref\n0 3\n0000000000 65535 f \n0000000010 00000 n \n0000000095 00000 n \ntrailer\n<< /Size 3 /Root 2 0 R >>\nstartxref\n150\n%%EOF\n"
    roster_content = b"INTERNAL STAFF DIRECTORY - Q3\n--------------------------------\nID: 1042 | John Doe       | Senior Analyst\nID: 1088 | Sarah Jenkins  | Lead Architect\nID: 1105 | Robert Vance   | Operations Officer\n"
    # JPEG Header mismatch file: Named "MEMO.TXT" but contains authentic JPEG header FF D8 FF E0
    fake_memo_jpeg = bytes([0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01, 0x01, 0x01, 0x00, 0x60, 0x00, 0x60, 0x00, 0x00]) + b"\xFE\x00\x28EXFILTRATED_SYSTEM_DIAGRAM_RESTRICTED_ACCESS" + bytes([0xFF, 0xD9])
    
    # Deleted confidential leak: CLIENTS.CSV
    leaked_clients = b"CLIENT_ID,ACCOUNT_NAME,CREDIT_LIMIT,ROUTING_KEY\nAC-8921,Apex Corp Holdings,5000000,ROUT-9921-XQ\nAC-9043,Global Vanguard Ltd,12000000,ROUT-4412-MK\nAC-9118,Nexus Defense Systems,35000000,TOP_SECRET_NX1\n"
    
    # Hidden secret notes with exfiltration instructions
    secret_notes = b"PROJECT BLACKOUT EXFILTRATION LOG\nDate: 2026-10-31\nTarget: Defense Contracts\nStatus: Copied to USB. Deleting client file before leaving building.\nDecryption Token: VmFuZ3VhcmRJbnRlZ3JpdHkyMDI2IQ==\n"

    files = [
        {"name": "POLICY  ", "ext": "PDF", "attr": 0x20, "data": policy_content, "deleted": False},
        {"name": "ROSTER  ", "ext": "TXT", "attr": 0x20, "data": roster_content, "deleted": False},
        {"name": "MEMO    ", "ext": "TXT", "attr": 0x20, "data": fake_memo_jpeg, "deleted": False},
        {"name": "CLIENTS ", "ext": "CSV", "attr": 0x20, "data": leaked_clients, "deleted": True}, # DELETED FILE!
        {"name": "NOTES   ", "ext": "TXT", "attr": 0x20, "data": secret_notes, "deleted": False},
    ]

    root_dir_offset = (reserved_sectors + num_fats * fat_size) * sector_size
    current_cluster = 2

    for f_idx, item in enumerate(files):
        data = item["data"]
        cluster_len = (len(data) + sector_size - 1) // sector_size
        start_cluster = current_cluster

        # Allocate in FAT
        for c in range(cluster_len):
            this_cluster = current_cluster + c
            if c == cluster_len - 1:
                set_fat12_entry(fat_table, this_cluster, 0xFFF) # EOF marker
            else:
                set_fat12_entry(fat_table, this_cluster, this_cluster + 1)
        
        # Write data to disk clusters
        data_sector = data_start_sector + (start_cluster - 2)
        disk_offset = data_sector * sector_size
        disk[disk_offset : disk_offset + len(data)] = data

        # Write Directory Entry (32 bytes)
        entry_offset = root_dir_offset + (f_idx * 32)
        name_bytes = bytearray(item["name"].encode("ascii"))
        if item["deleted"]:
            name_bytes[0] = 0xE5 # FAT Deleted marker!
        
        disk[entry_offset : entry_offset + 8] = name_bytes
        disk[entry_offset + 8 : entry_offset + 11] = item["ext"].encode("ascii")
        disk[entry_offset + 11] = item["attr"] # File attribute
        # Date & time stamps: 2026-11-02 10:15:30
        struct.pack_into("<H", disk, entry_offset + 22, 0x51E0) # Time
        struct.pack_into("<H", disk, entry_offset + 24, 0x5D62) # Date
        struct.pack_into("<H", disk, entry_offset + 26, start_cluster) # First cluster
        struct.pack_into("<I", disk, entry_offset + 28, len(data)) # File size

        current_cluster += cluster_len

    # Embed hidden string in unallocated slack space (e.g., sector 150)
    unallocated_sector = (data_start_sector + 20) * sector_size
    hidden_payload = b"CONFIDENTIAL_RECOVERY_KEY: DIT_CYBER_FORENSICS_LAB_2026_EVIDENCE_OK"
    disk[unallocated_sector : unallocated_sector + len(hidden_payload)] = hidden_payload

    # Copy FAT table to disk
    disk[fat1_offset : fat1_offset + len(fat_table)] = fat_table
    disk[fat2_offset : fat2_offset + len(fat_table)] = fat_table

    with open(filename, "wb") as f:
        f.write(disk)

    md5_hash = hashlib.md5(disk).hexdigest()
    sha256_hash = hashlib.sha256(disk).hexdigest()
    sha1_hash = hashlib.sha1(disk).hexdigest()

    print(f"Created forensic disk image: {filename}")
    print(f"Size: {len(disk)} bytes ({len(disk)/1024/1024:.2f} MB)")
    print(f"MD5   : {md5_hash}")
    print(f"SHA-1 : {sha1_hash}")
    print(f"SHA256: {sha256_hash}")
    return md5_hash, sha1_hash, sha256_hash

if __name__ == "__main__":
    os.makedirs("digital_forensics_project/evidence", exist_ok=True)
    create_fat12_disk("digital_forensics_project/evidence/suspect_device.dd")
