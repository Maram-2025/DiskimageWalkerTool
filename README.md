# DiskImageWalker

**DiskImageWalker** is a lightweight command-line tool for analyzing and recovering data from **FAT32 disk images** using Python.

The project is designed as a practical **Digital Forensics and Cybersecurity** tool that helps users understand how a FAT32 file system is structured, how deleted files are represented, how raw disk data can be inspected, and how file carving can be used to recover supported files.

The tool is implemented using **Python standard libraries only**, without relying on third-party packages.

## Project Overview

Deleting a file from a FAT32 file system does not necessarily mean that its actual data is immediately removed from the disk. In many cases, the directory entry is marked as deleted while the file's underlying data remains in the raw disk space until it is overwritten.

DiskImageWalker provides a transparent way to investigate this process by working directly with a disk image instead of the original physical disk.

The tool analyzes the disk image in several stages:

1. **Boot Sector Analysis**
   - Reads important FAT32 file-system information.
   - Displays values such as bytes per sector, sectors per cluster, FAT tables, and the beginning of the data region.

2. **FAT Table Analysis**
   - Reads the File Allocation Table (FAT).
   - Uses cluster information to understand the relationship between clusters and follow file or directory cluster chains.

3. **Directory Entry Analysis**
   - Reads root-directory entries.
   - Displays file names, file sizes, starting clusters, and file status.
   - Identifies directory entries marked as deleted.

4. **Raw Data Inspection**
   - Provides a `hexdump` command for inspecting raw disk data.
   - Displays selected data in both hexadecimal and ASCII representations.

5. **File Carving**
   - Searches raw disk data for known file signatures.
   - The current version supports **JPG and PNG** file carving.
   - Extracts detected files and saves them as independent files.

## Objectives

The main objectives of DiskImageWalker are to:

- Understand the FAT32 file system at the byte level.
- Understand the role of the Boot Sector, FAT, clusters, and directory entries.
- Analyze disk images without directly modifying or accessing the original physical disk.
- Identify existing and deleted files in the root directory.
- Inspect raw disk data using hexadecimal and ASCII representations.
- Apply file-carving techniques to recover JPG and PNG files.
- Provide a transparent implementation where the analysis process can be understood directly from the source code.
- Apply practical concepts from **Digital Forensics** and **Cybersecurity**.

## Features

- FAT32 Boot Sector parsing
- FAT table inspection
- Root Directory Entry analysis
- Detection of deleted directory entries
- Raw data inspection using Hex and ASCII
- JPG file carving
- PNG file carving
- Command-line interface (CLI)
- Python standard library only
- Disk-image based analysis

## Installation

Clone the repository:

```bash
git clone https://github.com/YOUR-USERNAME/DiskImageWalker.git
cd DiskImageWalker
```

No third-party Python packages are required.

Make sure Python 3 is installed:

```bash
python --version
```

## Usage

General syntax:

```bash
python diskimagewalker.py <command> <disk-image> [options]
```

### 1. Display FAT32 Information

```bash
python diskimagewalker.py info disk.img
```

This command reads the Boot Sector and displays information such as:

- Bytes per Sector
- Sectors per Cluster
- Cluster Size
- Reserved Sectors
- Number of FAT Tables
- FAT Size
- Root Cluster
- Beginning of the Data Region

### 2. List Directory Entries

```bash
python diskimagewalker.py list disk.img --all
```

This command analyzes the root directory and displays:

- Currently existing files
- Directories
- Files marked as deleted

The `--all` option allows deleted directory entries to be displayed as well.

### 3. Inspect Raw Data

```bash
python diskimagewalker.py hexdump disk.img --offset 0 --length 512
```

The command displays a selected section of the disk image in:

- Hexadecimal
- ASCII

This allows investigators to inspect the actual raw bytes stored in the disk image.

### 4. Recover Files Using File Carving

```bash
python diskimagewalker.py carve disk.img --output recovered --types jpg,png
```

The carving process searches the raw disk image for supported file signatures.

Currently supported file types:

- JPG
- PNG

When a valid file header is detected, the tool searches for the corresponding file ending and extracts the data into the specified output directory.

## Example Output

### `info`

```text
Boot Sector (FAT32)
-------------------
Bytes per Sector: 512
Sectors per Cluster: 1
Cluster Size: 512 bytes
Reserved Sectors: 32
Number of FATs: 1
Sectors per FAT: 8
Root Cluster: 2
Data Region Start Sector: 40
```

### `list --all`

```text
Root Directory
--------------

Existing:
[+] TEST.TXT
[+] secret_v2.txt

Deleted:
[x] LDFILE.TXT
```

### `hexdump`

The command displays raw disk data in hexadecimal and ASCII form:

```text
00000000 ...
00000010 ...
00000020 ...
```

### `carve`

Example recovery result:

```text
[+] Recovered 1 file
[+] recovered/carved_1.jpg
```

The recovered file is saved as an independent file inside the specified output directory.

## Digital Forensics Use Case

DiskImageWalker can be used as an educational tool for understanding basic digital-forensics workflows.

Instead of treating a forensic tool as a black box, the project demonstrates the underlying process:

```text
Disk Image
    |
    +-- Boot Sector
    |
    +-- FAT Table
    |
    +-- Directory Entries
    |
    +-- Raw Data
    |
    +-- File Carving
            |
            +-- JPG
            +-- PNG
```

This makes the project useful for students and beginners who want to understand how deleted-file analysis and file recovery work at a low level.

## Limitations

The current version has several limitations:

- It focuses on **FAT32** disk images.
- File carving currently supports **JPG and PNG**.
- Recovery depends on the file data still being present in the disk image.
- If the original file data has been overwritten, it may not be recoverable.
- The current implementation is primarily intended for educational and forensic-analysis purposes.

## Intended Users

DiskImageWalker can be useful for:

- Digital Forensics Analysts
- Cybersecurity Students
- Cybersecurity Analysts
- Digital Data Analysis Researchers
- Students learning file systems and disk forensics

## Disclaimer

DiskImageWalker is intended for **educational, research, and authorized digital-forensics purposes**.

Only analyze disk images and data that you are authorized to examine.

## Future Improvements

Possible future improvements include:

- Support for additional file systems such as NTFS and EXT.
- Support for more file types during file carving.
- Recursive directory analysis.
- Improved recovery of fragmented files.
- Additional forensic metadata extraction.
- Hash calculation for recovered files.
- Automated reporting of forensic findings.
- A graphical user interface (GUI).
- More advanced deleted-file recovery techniques.

## License

Copyright (C) 2026 Maram Mojeeb

DiskImageWalker is licensed under the GNU General Public License v3.0 (GPL-3.0).

See the [LICENSE](LICENSE) file for the full license text.

