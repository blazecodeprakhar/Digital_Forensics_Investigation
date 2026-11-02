# 🛡️ Digital Forensics Mini Investigation: Complete 0-to-100 Project Guide & Viva Voce Handbook

> **Project Author & Investigator:** [**blazecodeprakhar**](https://github.com/blazecodeprakhar)  
> **Official Repository:** [https://github.com/blazecodeprakhar/Digital_Forensics_Investigation_Report](https://github.com/blazecodeprakhar/Digital_Forensics_Investigation_Report)  
> **Watermark / Attribution:** `Authored by Prakhar Yadav (https://github.com/blazecodeprakhar)`  
> **Course / Degree:** Digital Forensics & Cyber Security (CSN302), School of Computing, DIT University Dehradun  
> **Investigation Case Ref:** `Case #DF-2026-INV12`

---

## 📑 TABLE OF CONTENTS
1. [Project Overview: Understanding from 0 to 100](#1-project-overview-understanding-from-0-to-100)
2. [The Three Unbreakable Pillars of Digital Forensics](#2-the-three-unbreakable-pillars-of-digital-forensics)
3. [The Case Scenario Explained (Case #DF-2026-INV12)](#3-the-case-scenario-explained-case-df-2026-inv12)
4. [Step-by-Step Technical Deep Dive (Under the Hood)](#4-step-by-step-technical-deep-dive-under-the-hood)
   * [Step 1: Evidence Media Synthesis & FAT12 Architecture](#step-1-evidence-media-synthesis--fat12-architecture)
   * [Step 2: Bit-Stream Acquisition & Write-Blocking](#step-2-bit-stream-acquisition--write-blocking)
   * [Step 3: Cryptographic Integrity & The Avalanche Effect](#step-3-cryptographic-integrity--the-avalanche-effect)
   * [Step 4: Autopsy Forensic Suite Ingestion](#step-4-autopsy-forensic-suite-ingestion)
   * [Step 5: Hex Analysis & Magic Number Mismatch Detection (HxD)](#step-5-hex-analysis--magic-number-mismatch-detection-hxd)
   * [Step 6: Forensic Carving & Recovering Deleted Files (`0xE5`)](#step-6-forensic-carving--recovering-deleted-files-0xe5)
   * [Step 7: Chain of Custody & Legal Admissibility](#step-7-chain-of-custody--legal-admissibility)
5. [Master Viva Voce Questions & High-Scoring Answers (35+ Questions)](#5-master-viva-voce-questions--high-scoring-answers)
   * [Category A: Digital Forensics Principles & Evidence Handling](#category-a-digital-forensics-principles--evidence-handling)
   * [Category B: Cryptographic Hashing, Integrity & Avalanche Effect](#category-b-cryptographic-hashing-integrity--avalanche-effect)
   * [Category C: File Systems, FAT Architecture & Data Carving](#category-c-file-systems-fat-architecture--data-carving)
   * [Category D: File Signatures, Magic Bytes & Anti-Forensics](#category-d-file-signatures-magic-bytes--anti-forensics)
   * [Category E: Real-World Scenarios, Court Admissibility & Laws](#category-e-real-world-scenarios-court-admissibility--laws)
6. [Quick Revision "Cheat Sheet" for Viva Day](#6-quick-revision-cheat-sheet-for-viva-day)

---

## 1. Project Overview: Understanding from 0 to 100

### What is this project in plain, simple terms?
Imagine an employee working at a sensitive corporation decides to steal confidential client databases and classified system blueprints before quitting. They plug in a personal USB drive, copy the secret files, and try to cover their tracks by:
1. **Renaming a classified blueprint** from a `.jpg` image into a harmless-looking `.txt` file (`MEMO.TXT`).
2. **Deleting the sensitive client records** (`CLIENTS.CSV`) so the folder looks clean.
3. **Concealing an exfiltration token** inside meeting notes.

This project is a **complete, hands-on simulation of what real-world cyber detectives (digital forensic analysts) do** when this device is seized:
* We **never plug the USB into a normal computer directly**, because Windows automatically writes hidden system files and changes timestamps, ruining the evidence.
* We place the drive behind a **Write-Blocker** and make an exact, sector-by-sector clone called a **Bit-Stream Physical Disk Image (`suspect_device.dd`)**.
* We use **Python hashlib** to calculate mathematical fingerprints (**MD5, SHA-1, SHA-256**) of the disk. If even 1 single bit changes in the future, the hash breaks completely (**Avalanche Effect**).
* We use **HxD Hex Editor** to inspect the raw binary bytes of the disk. We discover that `MEMO.TXT` is secretly a JPEG image because its very first bytes are `FF D8 FF E0` (JPEG magic number).
* We inspect the FAT File Allocation Table and find the deleted file: Windows didn't erase the file, it just replaced the first letter with the hex code `0xE5`. We trace the exact storage cluster and **carve 100% of the deleted confidential client list back to life**.
* We document every transfer in a **Chain of Custody Ledger** so the evidence can be presented in a court of law.

---

## 2. The Three Unbreakable Pillars of Digital Forensics

In any forensic evaluation, teachers always evaluate you on these three foundational principles:

```
┌────────────────────────────────────────────────────────────────────────┐
│                   THE 3 PILLARS OF DIGITAL FORENSICS                   │
├────────────────────┬────────────────────┬──────────────────────────────┤
│  1. ACQUISITION    │   2. INTEGRITY     │     3. CHAIN OF CUSTODY      │
│  (Preservation)    │  (Verification)    │     (Legal Accountability)   │
├────────────────────┼────────────────────┼──────────────────────────────┤
│ Never examine      │ Mathematical proof │ A signed paper/digital trail │
│ original media.    │ using MD5/SHA-256. │ showing who seized, imaged,   │
│ Always image with  │ If 1 bit changes,  │ analyzed, and secured the    │
│ a write-blocker.   │ evidence is void.  │ evidence at every second.    │
└────────────────────┴────────────────────┴──────────────────────────────┘
```

---

## 3. The Case Scenario Explained (Case #DF-2026-INV12)

* **Suspect:** Senior Enterprise Systems Administrator, Apex Corporate Holdings.
* **Incident Alert:** Security Operations Center (SOC) detected unauthorized mass storage enumeration on a high-security internal database server.
* **Seized Device:** SanDisk Removable Storage Device (Item `ITEM-01`), 1.41 MB capacity, formatted in FAT12.
* **Lead Forensic Examiner:** Prakhar Yadav ([blazecodeprakhar](https://github.com/blazecodeprakhar))

---

## 4. Step-by-Step Technical Deep Dive (Under the Hood)

### Step 1: Evidence Media Synthesis & FAT12 Architecture
A standard Windows folder cannot be forensically imaged because it lacks sector geometry, partition boot records, and unallocated slack space.  
Therefore, our Python engine ([`create_suspect_disk.py`](file:///c:/Users/prakh/OneDrive/Desktop/cyber_project/digital_forensics_project/scripts/create_suspect_disk.py)) synthesized a raw 1,474,560-byte binary image (`suspect_device.dd`) with standard FAT layout:

* **Sector 0 (Offset `0x00000000`): Master Boot Record & BPB (BIOS Parameter Block)**
  * OEM Identifier: `MSDOS5.0`
  * Sector Size: `512` bytes
  * Sectors per Cluster: `1`
  * Reserved Sectors: `1`
  * Number of FATs: `2` (FAT1 and FAT2 for redundancy)
  * Volume Label: `SUSPECT_USB`
  * Boot Signature at offset 510: `0x55 0xAA`
* **Sectors 1–9 (`0x00000200`): File Allocation Table 1 (FAT1)**
  * Maps which clusters belong to which file.
* **Sectors 10–18 (`0x00001400`): File Allocation Table 2 (FAT2)**
  * Redundant backup copy of FAT1.
* **Sectors 19–32 (`0x00002600`): Root Directory Table (224 entries @ 32 bytes each)**
  * Stores file names (8.3 format), attributes, timestamps, starting cluster pointers, and file sizes.
* **Sector 33+ (`0x00004200`): Data Area (Clusters 2 to 2879)**
  * The actual raw byte contents of the files.

---

### Step 2: Bit-Stream Acquisition & Write-Blocking
* **Write-Blocker Role:** When a storage drive is connected to a computer, Windows automatically updates volume timestamps, creates `System Volume Information`, and writes thumbnail caches. A **Hardware Write-Blocker** (such as Tableau T8u) intercepts SCSI/USB write commands at the physical bus layer and drops them, making the device 100% read-only.
* **Physical Acquisition:** Using **FTK Imager**, we choose `Physical Drive` rather than `Logical Drive`.
  * *Logical acquisition* only copies visible files.
  * *Physical bit-stream acquisition* copies every single sector (0 to 2,879), capturing **allocated files, deleted files, file slack, and unallocated space**.
* **Output Format:** Raw DD format (`.dd`).

---

### Step 3: Cryptographic Integrity & The Avalanche Effect
To prove that our acquired image (`suspect_device.dd`) was not modified, our script ([`forensic_hasher.py`](file:///c:/Users/prakh/OneDrive/Desktop/cyber_project/digital_forensics_project/scripts/forensic_hasher.py)) reads the disk in 64 KB blocks and computes three independent cryptographic digests:

* **MD5:** `8b71c348840eb453e0314961737ac26a`
* **SHA-1:** `cf4850eb15729162732448cbeeaf7e17acb9475f`
* **SHA-256 (Master Baseline):** `3b5a7762f2c49c891da888c8be90f5c67baa4fdecda9c2764d94a8845e75a01c`

#### 💥 The Cryptographic Avalanche Effect Experiment:
We copied the image to `suspect_device_tampered.dd` and flipped **exactly 1 bit** at byte offset 1024 (`data[1024] ^= 0x01`):
* **Original SHA-256:** `3b5a7762f2c49c891da888c8be90f5c67baa4fdecda9c2764d94a8845e75a01c`
* **Tampered SHA-256:** `fbff387a8a75e60dc92bb16c9bb58dad222bd0389d26304fe69e913c2180fdad`
* **Result:** **127 of 256 bits altered (49.61%)**.  
  This demonstrates the **Strict Avalanche Criterion (SAC)** defined in NIST FIPS 180-4: even an undetectable microscopic modification completely scrambles the output hash, proving that the evidence has been tampered with.

---

### Step 4: Autopsy Forensic Suite Ingestion
We load `suspect_device.dd` into **Autopsy 4.21.0**:
* Autopsy parses partition tables and file structures automatically.
* Under the **Views -> Extension Mismatch** panel, Autopsy raises a high-priority alert for `MEMO.TXT`.
* Under **Views -> Deleted Files**, Autopsy identifies `_LIENTS.CSV`.
* Under **Keyword Search**, searching for `CONFIDENTIAL` reveals two hits: the deleted client spreadsheet and a hidden recovery string in unallocated sectors.

---

### Step 5: Hex Analysis & Magic Number Mismatch Detection (HxD)
Suspects often rename file extensions (e.g., renaming `malware.exe` to `photo.jpg` or `secret.pdf` to `memo.txt`). However, operating systems and software do not determine the true nature of a file by its extension; they inspect the **Magic Bytes (File Signature)** at byte offset 0.

Opening `MEMO_DISGUISED_IMAGE.TXT` in **HxD Hex Editor** reveals:
```
Offset(h)  00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F   Decoded text
00000000  FF D8 FF E0 00 10 4A 46  49 46 00 01 01 01 00 60   ......JFIF.....`
00000010  00 60 00 00 FE 00 28 45  58 46 49 4C 54 52 41 54   .`....(EXFILTRAT
00000020  45 44 5F 53 59 53 54 45  4D 5F 44 49 41 47 52 41   ED_SYSTEM_DIAGRA
00000030  4D 5F 52 45 53 54 52 49  43 54 45 44 5F 41 43 43   M_RESTRICTED_ACC
00000040  45 53 53 FF D9                                     ESS..
```
* `FF D8 FF`: Magic signature for a JPEG image (SOI - Start of Image).
* `E0 00 10 4A 46 49 46`: JFIF application marker.
* `FE 00`: JPEG Comment marker containing the text: `EXFILTRATED_SYSTEM_DIAGRAM_RESTRICTED_ACCESS`.
* `FF D9`: JPEG End of Image (EOI) marker.
* **Forensic Conclusion:** The suspect intentionally spoofed the extension to conceal an exfiltrated architectural diagram.

---

### Step 6: Forensic Carving & Recovering Deleted Files (`0xE5`)
When a file is deleted in FAT (FAT12/FAT16/FAT32):
1. **The operating system DOES NOT wipe the data clusters.** The contents remain untouched on disk.
2. The operating system only changes the **first byte of the file's 32-byte directory entry** to the hex value `0xE5` (229 in decimal).
3. The FAT table entries are set to `0x000` (free/unallocated), allowing future files to overwrite those clusters.

In HxD, inspecting the Root Directory table at offset `0x00002660`:
* Bytes: `E5 4C 49 45 4E 54 53 20 43 53 56` (`_LIENTS CSV`).
* Offset `0x0000267A` (Starting cluster pointer): `0x0005` (Cluster 5).
* Offset `0x0000267C` (File size in bytes): `0x000000C8` (200 bytes).

Our carver script ([`hex_analyzer.py`](file:///c:/Users/prakh/OneDrive/Desktop/cyber_project/digital_forensics_project/scripts/hex_analyzer.py)) navigated directly to Cluster 5 (Sector 36, offset `0x00004800`) and carved the full 200 bytes into [**`RECOVERED__LIENTS.CSV`**](file:///c:/Users/prakh/OneDrive/Desktop/cyber_project/digital_forensics_project/evidence/RECOVERED__LIENTS.CSV):
```csv
CLIENT_ID,ACCOUNT_NAME,CREDIT_LIMIT,ROUTING_KEY
AC-8921,Apex Corp Holdings,5000000,ROUT-9921-XQ
AC-9043,Global Vanguard Ltd,12000000,ROUT-4412-MK
AC-9118,Nexus Defense Systems,35000000,TOP_SECRET_NX1
```
**Forensic Result:** 100% of the confidential defense client database was recovered with zero data loss.

---

### Step 7: Chain of Custody & Legal Admissibility
Any forensic finding is worthless in court without a verified Chain of Custody. Our ledger tracks:
1. **Physical Device (ITEM-01):** Seized from suspect by incident response team, secured in anti-static evidence bag.
2. **Raw Disk Image (ITEM-02):** Created under write-blocker isolation, verified by primary examiner, SHA-256 recorded.
3. **Working Copy (ITEM-03):** Verified duplicate copy used for tamper-testing; master hash matched.
4. **Carved Artifact (ITEM-04):** Extracted client database with independent SHA-256 checksum.
5. **Final Judicial Report (ITEM-05):** Master forensic report package verified and sealed.

**Statutory Admissibility:** Admissible under **Section 65B of the Indian Evidence Act** and **Federal Rules of Evidence (FRE) Rule 902(11)/(14)** for self-authenticating digital records.

---

## 5. Master Viva Voce Questions & High-Scoring Answers

Below are the exact theoretical and practical questions examiners love to ask in digital forensics vivas, along with model answers.

---

### Category A: Digital Forensics Principles & Evidence Handling

#### Q1: What are the primary objectives of Digital Forensics?
> **Model Answer:** The primary objective of digital forensics is to identify, preserve, extract, analyze, and present digital evidence in a scientifically sound and legally admissible manner, establishing an indisputable audit trail (Chain of Custody) that withstands judicial scrutiny.

#### Q2: Why should you NEVER analyze or examine the original evidence media directly?
> **Model Answer:** Direct interaction with original media causes data contamination. Operating systems automatically modify file access timestamps (ATime), create temporary thumbnail databases, and alter metadata. An analyst must always create a bit-stream physical image under write-blocker protection and perform all investigations on verified duplicate working copies.

#### Q3: What is the difference between a Physical Disk Image and a Logical Disk Image?
> **Model Answer:**
> * **Logical Disk Image:** Captures only currently active, visible files and folders indexed by the operating system's file system. It ignores unallocated space and deleted data.
> * **Physical Bit-Stream Disk Image (e.g., raw `.dd`):** A sector-by-sector clone of the physical storage media from Sector 0 to the final sector. It captures allocated sectors, unallocated space, volume slack, partition tables, and deleted file remnants.

#### Q4: What is a Write-Blocker, and how does it function?
> **Model Answer:** A write-blocker is a hardware device (e.g., Tableau T8u) or software driver that intercepts input/output commands directed to a storage medium. It permits all read commands (`SCSI READ`, `ATA READ`) to pass through while intercepting, blocking, and discarding any write, erase, or modify commands, guaranteeing that the target disk cannot be altered during imaging.

#### Q5: What is the difference between Raw (dd) format and Expert Witness Format (E01)?
> **Model Answer:**
> * **Raw (dd):** An uncompressed, raw sector-by-sector copy containing only raw data bytes with no embedded metadata.
> * **E01 (EnCase / Expert Witness Format):** Encapsulates the raw disk sectors within structured blocks accompanied by embedded case information (case number, examiner, date), block-level CRC32 checksums, and header/footer MD5 and SHA-1 hashes.

---

### Category B: Cryptographic Hashing, Integrity & Avalanche Effect

#### Q6: What is a Cryptographic Hash Function, and why is it used in Forensics?
> **Model Answer:** A cryptographic hash function is a one-way mathematical algorithm that takes an arbitrary-sized block of data and computes a unique, fixed-size bit string (digest). In digital forensics, it serves as an immutable digital fingerprint used to verify evidence integrity, detect tampering, and provide mathematical non-repudiation in court.

#### Q7: Why do we calculate multiple hashes (e.g., MD5, SHA-1, and SHA-256) instead of just one?
> **Model Answer:** While MD5 (128-bit) and SHA-1 (160-bit) are fast and legacy standards, theoretical hash collision vulnerabilities have been demonstrated against them. SHA-256 (256-bit) provides robust collision resistance. Calculating both MD5 and SHA-256 provides backward compatibility with legacy court records while ensuring future-proof mathematical security against collision attacks.

#### Q8: Explain the "Avalanche Effect" and its significance in digital forensics.
> **Model Answer:** The Strict Avalanche Criterion (SAC) states that if an input is changed by even a single bit, approximately 50% of the output hash digest bits must change unpredictably. In digital forensics, this proves that any evidence modification—whether deliberate tampering or accidental corruption—is immediately obvious because the resulting hash changes completely.

#### Q9: In your project, what happened when you flipped 1 bit in `suspect_device_tampered.dd`?
> **Model Answer:** We flipped bit 0 at byte offset 1024 using an XOR mask (`0x01`). The resulting SHA-256 digest completely diverged from `3b5a...` to `fbff...`. A Hamming distance calculation confirmed that **127 out of 256 bits (49.61%)** changed, proving the Avalanche Effect and resulting in immediate rejection of the tampered copy.

#### Q10: How does your Python hashing script handle large multi-gigabyte disk images without running out of RAM?
> **Model Answer:** The script reads the disk image in fixed-size chunks (64 KB / 65,536 bytes) using an iterative loop (`iter(lambda: f.read(chunk_size), b'')`) and updates the hash digest incrementally (`h.update(chunk)`). This ensures a constant, microscopic memory footprint regardless of whether the image is 1 MB or 2 TB.

---

### Category C: File Systems, FAT Architecture & Data Carving

#### Q11: What is a Sector, a Cluster, and Slack Space?
> **Model Answer:**
> * **Sector:** The smallest physical storage unit on a drive, traditionally 512 bytes (or 4096 bytes in Advanced Format).
> * **Cluster (Allocation Unit):** The smallest logical amount of disk space the operating system can allocate to hold a file (composed of 1 or more sectors).
> * **File Slack (Slack Space):** The unused space between the actual end of a file's data and the end of the cluster allocated to that file. Forensic investigators inspect slack space because it frequently contains residual data from previously deleted files.

#### Q12: How does a FAT (File Allocation Table) file system delete a file?
> **Model Answer:** In FAT file systems (FAT12, FAT16, FAT32), the operating system does not overwrite the file's data when deleted. Instead, it performs two fast operations:
> 1. It replaces the first ASCII character of the file's 32-byte root directory entry with the hex byte **`0xE5`** (sigma `σ` in OEM codepage).
> 2. It marks the corresponding entries in the FAT table as `0x000` (available for future allocation).  
> The underlying data clusters remain completely intact until another file overwrites them.

#### Q13: What is "File Carving" or "Data Carving"?
> **Model Answer:** File carving is the forensic technique of extracting files from raw disk sectors or unallocated space without relying on file system metadata (such as directory tables or MFTs). It works by identifying known file headers (magic bytes), file footers/trailers, or starting cluster pointers and reconstructing the contiguous byte stream.

#### Q14: How did your project recover the deleted `CLIENTS.CSV` file?
> **Model Answer:** We inspected the FAT12 root directory table at offset `0x00002660`, where we identified the entry starting with `0xE5` followed by `LIENTS  CSV`. The directory entry retained the starting cluster number (`0x0005`) and file size (`200 bytes`). By calculating the byte offset of Cluster 5 (`0x00004800`), our Python script carved the 200 bytes directly from raw sectors, recovering all records intact.

---

### Category D: File Signatures, Magic Bytes & Anti-Forensics

#### Q15: What is a File Signature (Magic Number)?
> **Model Answer:** A file signature (magic number) is a specific sequence of hexadecimal bytes placed at the very beginning of a file (offset 0) that unambiguously defines its true MIME type and structure, regardless of whatever extension the user assigns to the file.

#### Q16: Give common examples of magic numbers.
> **Model Answer:**
> * **JPEG:** `FF D8 FF E0` or `FF D8 FF E1` (Ends with `FF D9`)
> * **PDF:** `25 50 44 46` (`%PDF`)
> * **ZIP / DOCX / XLSX:** `50 4B 03 04` (`PK..`)
> * **PNG:** `89 50 4E 47 0D 0A 1A 0A` (`\x89PNG\r\n\x1a\n`)
> * **Executable (EXE/DLL):** `4D 5A` (`MZ` - Mark Zbikowski)

#### Q17: What anti-forensic attempt did the suspect make with `MEMO.TXT`, and how did you detect it?
> **Model Answer:** The suspect attempted **Extension Spoofing** by renaming an exfiltrated architectural diagram from `.jpg` to `.txt` (`MEMO.TXT`). We detected this by examining the file's first 16 bytes in HxD, which began with `FF D8 FF E0` (JPEG JFIF) rather than ASCII text. Autopsy also flagged this under its automated **Extension Mismatch** ingest module.

#### Q18: What is Anti-Forensics? Name three common anti-forensic techniques.
> **Model Answer:** Anti-forensics refers to measures taken by malicious actors to hinder, delay, or prevent forensic discovery, analysis, or attribution. Three common techniques are:
> 1. **Extension Spoofing & Header Tampering** (disguising file types).
> 2. **Data Wiping / Multi-Pass Sanitization** (overwriting sectors with zeroes or pseudorandom patterns, e.g., DoD 5220.22-M).
> 3. **Full Volume / Container Encryption** (using VeraCrypt or BitLocker to conceal file systems).

---

### Category E: Real-World Scenarios, Court Admissibility & Laws

#### Q19: Why is a Chain of Custody document legally critical?
> **Model Answer:** In judicial proceedings, evidence is inadmissible if the opposing party can prove reasonable doubt regarding evidence tampering, contamination, or substitution. An unbroken Chain of Custody proves that from the instant the device was seized until its presentation in court, every custodian, timestamp, purpose, and cryptographic checksum is accounted for.

#### Q20: What legal provisions govern digital evidence admissibility in India and the United States?
> **Model Answer:**
> * **India:** **Section 65B of the Indian Evidence Act, 1872** (now Bharatiya Sakshya Adhiniyam, 2023), which requires a formal certificate detailing the device identification, hash verification, operating conditions, and custodial integrity.
> * **United States:** **Federal Rules of Evidence (FRE) Rule 902(13) and Rule 902(14)**, which permit digital evidence to be self-authenticating when certified by a qualified examiner with verifiable cryptographic hash processes.

#### Q21: What are the forensic challenges posed by modern Solid-State Drives (SSDs)?
> **Model Answer:** Modern SSDs utilize flash memory with background wear-leveling and the **SATA/NVMe TRIM command**. When a file is deleted on an SSD, the operating system informs the drive controller that those blocks are free; the drive controller actively zeroes or garbage-collects those physical flash cells in the background. Unlike magnetic hard drives or FAT USB flash drives, deleted files on SSDs often become completely unrecoverable within seconds.

---

## 6. Quick Revision "Cheat Sheet" for Viva Day

Before walking into your viva room, commit these quick technical facts to memory:

```
┌────────────────────────────────────────────────────────────────────────┐
│                      FORENSIC VIVA CHEAT SHEET                         │
├─────────────────────────┬──────────────────────────────────────────────┤
│ Metric / Concept        │ Value / Answer to State                      │
├─────────────────────────┼──────────────────────────────────────────────┤
│ Case Number             │ Case #DF-2026-INV12                          │
│ Suspect Device Size     │ 1,474,560 Bytes (1.41 MB, 2,880 Sectors)     │
│ File System Used        │ FAT12 (SUSPECT_USB, OEM: MSDOS5.0)           │
│ Sector Size             │ 512 Bytes                                    │
│ FAT Deletion Byte       │ 0xE5 (Replaces first character in Dir Table) │
│ Master SHA-256 Hash     │ 3b5a7762f2c49c891da888c8be90f5c67baa...     │
│ Avalanche Shift Rate    │ 127 of 256 bits (49.61%) upon 1-bit flip     │
│ JPEG Magic Number       │ FF D8 FF E0 (Start) / FF D9 (End)            │
│ PDF Magic Number        │ 25 50 44 46 (%PDF)                           │
│ Carved File Recovered   │ CLIENTS.CSV from Cluster 5 (Offset 0x4800)   │
│ Relevant Standards      │ ISO/IEC 27037 & NIST SP 800-86               │
│ Legal Framework         │ Section 65B Indian Evidence Act / FRE 902    │
└─────────────────────────┴──────────────────────────────────────────────┘
```

---

> **Official Watermark & Attribution:**  
> Project and Guide Authored by: **Prakhar Yadav**  
> GitHub Profile: [https://github.com/blazecodeprakhar](https://github.com/blazecodeprakhar)  
> Repository: [https://github.com/blazecodeprakhar/Digital_Forensics_Investigation_Report](https://github.com/blazecodeprakhar/Digital_Forensics_Investigation_Report)
