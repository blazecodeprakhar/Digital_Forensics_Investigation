import hashlib
import sys
import os

def calculate_hashes(filepath, chunk_size=65536):
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while True:
            data = f.read(chunk_size)
            if not data:
                break
            md5.update(data)
            sha1.update(data)
            sha256.update(data)
    return {
        'file': os.path.basename(filepath),
        'size': os.path.getsize(filepath),
        'md5': md5.hexdigest(),
        'sha1': sha1.hexdigest(),
        'sha256': sha256.hexdigest()
    }

def verify_evidence(evidence_file, baseline_sha256):
    res = calculate_hashes(evidence_file)
    is_match = (res['sha256'].lower() == baseline_sha256.lower())
    return res, is_match

def demonstrate_avalanche_effect(original_file, tampered_file):
    with open(original_file, 'rb') as f:
        data = bytearray(f.read())
    data[1024] ^= 0x01
    with open(tampered_file, 'wb') as f:
        f.write(data)
    orig_hashes = calculate_hashes(original_file)
    tamp_hashes = calculate_hashes(tampered_file)
    return orig_hashes, tamp_hashes

if __name__ == '__main__':
    target = 'digital_forensics_project/evidence/suspect_device.dd'
    if len(sys.argv) > 1:
        target = sys.argv[1]
    results = calculate_hashes(target)
    print('========================================================')
    print('  DIGITAL FORENSICS INTEGRITY & HASH VERIFICATION TOOL  ')
    print('========================================================')
    print(f'Evidence File    : {results["file"]}')
    print(f'File Size (Bytes): {results["size"]}')
    print(f'MD5 Hash         : {results["md5"]}')
    print(f'SHA-1 Hash       : {results["sha1"]}')
    print(f'SHA-256 Hash     : {results["sha256"]}')
    print('--------------------------------------------------------')
    
    baseline = '3b5a7762f2c49c891da888c8be90f5c67baa4fdecda9c2764d94a8845e75a01c'
    res, match = verify_evidence(target, baseline)
    if match:
        print('[VERIFICATION RESULT] INTEGRITY INTACT: Hash matches baseline.')
    else:
        print('[VERIFICATION RESULT] ALERT: Hash mismatch! Evidence tampered.')
    print('--------------------------------------------------------')
    
    tampered_path = 'digital_forensics_project/evidence/suspect_device_tampered.dd'
    orig_h, tamp_h = demonstrate_avalanche_effect(target, tampered_path)
    print('[AVALANCHE EFFECT DEMONSTRATION - SINGLE BIT FLIP AT OFFSET 1024]')
    print(f'Original SHA-256 : {orig_h["sha256"]}')
    print(f'Tampered SHA-256 : {tamp_h["sha256"]}')
    bit_diff = sum(bin(int(orig_h['sha256'], 16) ^ int(tamp_h['sha256'], 16)).count('1') for _ in [1])
    print(f'Bit Difference in Digest: {bit_diff} of 256 bits changed (~{(bit_diff/256)*100:.1f}%)')
    print('========================================================')
