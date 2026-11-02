# Digital Forensics Mini Investigation with Chain of Custody and Report

Developed as part of the academic curriculum for the **Bachelor of Technology in Cybersecurity and Privacy**, School of Computing, **DIT University, Dehradun**.

---

## 📌 Case Scenario Overview (Case #DF-2026-INV12)

* **Incident:** An employee suspected of corporate espionage and unauthorized data exfiltration connected a removable flash device to a restricted corporate workstation, attempting to steal classified defense client portfolios and system architectural schematics.
* **Anti-Forensic Techniques Attempted by Suspect:**
  1. **Extension Spoofing:** Disguised an exfiltrated architectural JPEG diagram as a plain text file (`MEMO.TXT`).
  2. **File Deletion:** Deleted the high-value client records spreadsheet (`CLIENTS.CSV`) to evade detection before device seizure.
  3. **Data Concealment:** Embedded hidden exfiltration notes with Base64 decryption tokens (`NOTES.TXT`) and residual credentials in unallocated sectors.
* **Investigative Mission:** Perform forensically sound physical bit-stream imaging, calculate and verify multi-algorithm cryptographic hashes, maintain an unbroken Chain of Custody, expose disguised file signatures, and carve the deleted database from raw sectors.

---

## 🔬 Core Forensic Pillars

1. **Forensic Acquisition (Preservation):**  
   Bit-stream physical disk imaging (`suspect_device.dd`) acquired under hardware write-blocker protection to guarantee zero alteration of evidentiary sectors or access timestamps.
2. **Cryptographic Integrity (Non-Repudiation):**  
   Verification via Python `hashlib` using MD5, SHA-1, and SHA-256. Proof of tamper detection through the **Strict Avalanche Criterion (SAC)** (inverting a single bit changes ~50% of the SHA-256 digest).
3. **Chain of Custody (Legal Admissibility):**  
   Chronological, signed tracking ledger documenting seizing officers, custodial transfers, analytical purposes, timestamps, and matching SHA-256 checksums to meet **ISO/IEC 27037** and court admissibility requirements.

---

## 🛠️ Tools & Technologies Used

| Tool / Technology | Version / Specification | Purpose in Investigation |
| :--- | :--- | :--- |
| **AccessData FTK Imager** | v4.7.1 | Physical raw bit-stream drive imaging & baseline hash computation |
| **Autopsy Forensic Browser** | v4.21.0 | Data source ingestion, MIME type categorization & deleted artifact indexing |
| **Python Runtime** | v3.13.3 | Custom hash verification engine, block hashing & automated cluster carver |
| **HxD Hex Editor** | v2.5.0 (64-bit) | Raw sector inspection, file signature (magic number) verification & byte analysis |
| **Windows PowerShell** | Native ConHost | Real-time command-line execution and live verification |
| **Suspect Media Image** | FAT12 (1.41 MB) | Physical 2,880-sector disk image with boot sector, FAT tables, and data clusters |

---

## 📂 Project Repository Structure

```text
├── Digital_Forensics_Investigation_Report.docx   # Complete submission lab report
├── README.md                                     # Project overview and documentation
├── .gitignore                                    # Clean repository exclusion rules
└── digital_forensics_project/
    ├── evidence/                                 # Forensic disk image & carved artifacts
    │   ├── suspect_device.dd                     # 1:1 physical raw disk image (1.41 MB)
    │   ├── suspect_device_tampered.dd            # 1-bit modified image for tamper testing
    │   ├── MEMO_DISGUISED_IMAGE.TXT              # Spoofed file containing JPEG magic bytes
    │   └── RECOVERED__LIENTS.CSV                 # 100% carved confidential client database
    ├── screenshots/                              # Live captured terminal & HxD screenshots
    │   ├── terminal_hasher.png                   # Python MD5/SHA-1/SHA-256 verification
    │   ├── terminal_avalanche.png                # Avalanche effect & 1-bit tamper proof
    │   ├── terminal_carver.png                   # FAT directory parsing & data carving
    │   ├── hxd_suspect_disk.png                  # HxD raw disk inspection (Sector 0)
    │   ├── hxd_signature_mismatch.png            # HxD JPEG magic bytes in MEMO.TXT
    │   └── hxd_carved_client.png                 # HxD view of recovered client records
    └── scripts/                                  # Forensic Python automation scripts
        ├── create_suspect_disk.py                # Raw FAT12 evidence media synthesizer
        ├── forensic_hasher.py                    # Chunked block hashing & baseline verifier
        └── hex_analyzer.py                       # Magic byte checker & cluster carver
```

---

## 🚀 How to Run the Investigation Scripts

### 1. Re-generate or Inspect the Evidence Media
```bash
python digital_forensics_project/scripts/create_suspect_disk.py
```
*Creates the 2,880-sector (1,474,560 bytes) physical raw disk image with real FAT boot sectors, root directory tables, and active/deleted files.*

### 2. Verify Cryptographic Hashes & Tamper Detection
```bash
python digital_forensics_project/scripts/forensic_hasher.py
```
*Outputs MD5, SHA-1, and SHA-256 checksums, compares against baseline acquisition values, and executes the 1-bit Avalanche Effect demonstration.*

### 3. Parse File System, Detect Extension Mismatch & Carve Deleted Files
```bash
python digital_forensics_project/scripts/hex_analyzer.py
```
*Scans 32-byte FAT directory entries, detects the `0xE5` deletion flag, alerts on file signature mismatches, carves `RECOVERED__LIENTS.CSV` from cluster 5, and scans unallocated space for hidden strings.*

---

## 🔍 Key Findings Summary

* **Baseline Disk Image Hashes:**
  * **MD5:** `8b71c348840eb453e0314961737ac26a`
  * **SHA-1:** `cf4850eb15729162732448cbeeaf7e17acb9475f`
  * **SHA-256:** `3b5a7762f2c49c891da888c8be90f5c67baa4fdecda9c2764d94a8845e75a01c`
* **Tamper Proof (Avalanche Effect):**
  * Toggling a single bit at byte offset 1024 altered **127 of 256 bits (49.61%)** in the SHA-256 digest, immediately invalidating the file and proving evidence tampering.
* **Extension Spoofing Detected:**
  * `MEMO.TXT` reported a `.TXT` extension but had magic bytes `FF D8 FF E0 00 10 4A 46 49 46` (JPEG JFIF) and an embedded comment `EXFILTRATED_SYSTEM_DIAGRAM_RESTRICTED_ACCESS`.
* **Deleted File Recovery:**
  * `CLIENTS.CSV` was marked deleted (`0xE5 4C 49 45 4E 54 53`), but its cluster 5 pointer (offset `0x4800`) remained intact. Carving extracted all confidential defense client records and routing keys without loss.

---

## 📜 References

1. **Carrier, B. (2005).** *File System Forensic Analysis.* Addison-Wesley Professional.
2. **NIST Special Publication 800-86:** *Guide to Integrating Forensic Techniques into Incident Response.*
3. **ISO/IEC 27037:2012:** *Guidelines for identification, collection, acquisition and preservation of digital evidence.*
4. **FIPS PUB 180-4:** *Secure Hash Standard (SHS).* National Institute of Standards and Technology.
5. **RFC 1321:** *The MD5 Message-Digest Algorithm.* Internet Engineering Task Force.
