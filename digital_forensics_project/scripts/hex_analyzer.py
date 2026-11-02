import struct
import sys
import os

SIGNATURES = {
    b'\xFF\xD8\xFF': ('JPEG Image', '.jpg'),
    b'%PDF': ('PDF Document', '.pdf'),
    b'PK\x03\x04': ('ZIP Archive / Office XML', '.zip'),
    b'\x89PNG\r\n\x1a\n': ('PNG Image', '.png'),
    b'GIF87a': ('GIF Image', '.gif'),
    b'GIF89a': ('GIF Image', '.gif')
}

def identify_signature(header_bytes):
    for sig, (desc, ext) in SIGNATURES.items():
        if header_bytes.startswith(sig):
            return desc, ext
    return 'Plain Text / Binary Raw Data', None

def hex_dump_sector(data, offset, length=256):
    lines = []
    chunk = data[offset : offset + length]
    for i in range(0, len(chunk), 16):
        sub = chunk[i : i + 16]
        hex_bytes = ' '.join(f'{b:02X}' for b in sub)
        ascii_chars = ''.join(chr(b) if 32 <= b < 127 else '.' for b in sub)
        lines.append(f'{offset + i:08X}  {hex_bytes:<48}  |{ascii_chars}|')
    return '\n'.join(lines)

def parse_fat12_evidence(image_path):
    with open(image_path, 'rb') as f:
        disk = f.read()
    
    sector_size = struct.unpack_from('<H', disk, 11)[0]
    reserved_sectors = struct.unpack_from('<H', disk, 14)[0]
    num_fats = disk[16]
    root_entries = struct.unpack_from('<H', disk, 17)[0]
    fat_size = struct.unpack_from('<H', disk, 22)[0]
    
    root_dir_offset = (reserved_sectors + num_fats * fat_size) * sector_size
    data_start_sector = reserved_sectors + (num_fats * fat_size) + ((root_entries * 32 + sector_size - 1) // sector_size)
    
    artifacts = []
    
    for i in range(root_entries):
        entry_offset = root_dir_offset + (i * 32)
        raw_entry = disk[entry_offset : entry_offset + 32]
        if raw_entry[0] == 0x00:
            break
        
        is_deleted = (raw_entry[0] == 0xE5)
        raw_name = raw_entry[0:8]
        if is_deleted:
            name_str = '_' + raw_name[1:8].decode('ascii', errors='ignore').strip()
        else:
            name_str = raw_name.decode('ascii', errors='ignore').strip()
            
        ext_str = raw_entry[8:11].decode('ascii', errors='ignore').strip()
        attr = raw_entry[11]
        start_cluster = struct.unpack_from('<H', raw_entry, 26)[0]
        file_size = struct.unpack_from('<I', raw_entry, 28)[0]
        
        cluster_offset = (data_start_sector + (start_cluster - 2)) * sector_size
        file_payload = disk[cluster_offset : cluster_offset + file_size]
        
        detected_type, expected_ext = identify_signature(file_payload[:16])
        extension_mismatch = False
        if expected_ext and ('.' + ext_str.lower() != expected_ext.lower()):
            extension_mismatch = True
            
        artifacts.append({
            'name': f'{name_str}.{ext_str}',
            'status': 'DELETED (Recoverable)' if is_deleted else 'ACTIVE',
            'size': file_size,
            'cluster': start_cluster,
            'offset': cluster_offset,
            'detected_type': detected_type,
            'mismatch': extension_mismatch,
            'data': file_payload
        })
        
    return disk, artifacts

if __name__ == '__main__':
    path = 'digital_forensics_project/evidence/suspect_device.dd'
    if len(sys.argv) > 1:
        path = sys.argv[1]
    
    disk_data, findings = parse_fat12_evidence(path)
    
    print('========================================================')
    print('      DIGITAL FORENSICS ARTIFACT & HEX ANALYZER         ')
    print('========================================================')
    print(f'Target Image: {path}')
    print(f'Total Detected File System Entries: {len(findings)}\n')
    
    print(f'{"Filename":<14} | {"Status":<22} | {"Size":<6} | {"True File Type":<22} | {"Mismatch"}')
    print('-' * 80)
    for art in findings:
        mis_flag = 'YES (ALERT)' if art['mismatch'] else 'NO'
        print(f'{art["name"]:<14} | {art["status"]:<22} | {art["size"]:<6} | {art["detected_type"]:<22} | {mis_flag}')
        
    print('\n--------------------------------------------------------')
    print('[DEEP DIVE: FILE SIGNATURE & EXTENSION MISMATCH INSPECTION]')
    for art in findings:
        if art['mismatch']:
            print(f'Spoofed File Identified: {art["name"]}')
            print(f'Reported Extension    : .{art["name"].split(".")[-1]}')
            print(f'Actual True Magic Type: {art["detected_type"]}')
            print('Hex Dump of Initial File Header (First 64 Bytes):')
            print(hex_dump_sector(disk_data, art['offset'], 64))
            print()
            
    print('--------------------------------------------------------')
    print('[DEEP DIVE: DELETED FILE RECOVERY - FORENSIC CARVING]')
    for art in findings:
        if 'DELETED' in art['status']:
            print(f'Carving Deleted File: {art["name"]}')
            print(f'Allocated Cluster   : {art["cluster"]} (Byte Offset: {art["offset"]:#x})')
            print(f'Recovered Data Size : {art["size"]} bytes')
            print('Recovered Content Preview:')
            print(art['data'].decode('ascii', errors='replace'))
            recovered_path = os.path.join('digital_forensics_project/evidence', f'RECOVERED_{art["name"]}')
            with open(recovered_path, 'wb') as rec_f:
                rec_f.write(art['data'])
            print(f'Saved carved file to: {recovered_path}\n')
            
    print('--------------------------------------------------------')
    print('[DEEP DIVE: UNALLOCATED SLACK SPACE STRING SCAN]')
    kw = b'CONFIDENTIAL'
    kw_pos = disk_data.find(kw)
    if kw_pos != -1:
        print(f'Suspicious Unallocated Keyword Found at Offset: {kw_pos:#x}')
        print(hex_dump_sector(disk_data, kw_pos - 16, 96))
    print('========================================================')
