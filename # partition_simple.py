

import struct

IMAGE_PATH = r"D:\Disk image forensics\CW Image.dd"
SECTOR_SIZE = 512

def read_sector(f, lba=0):
    f.seek(lba * SECTOR_SIZE)
    return f.read(SECTOR_SIZE)

def parse_mbr(mbr):
    print("=== MBR Partition Table ===")
    base = 0x1BE  # MBR partition entries start here
    for i in range(4):
        entry = mbr[base + (i * 16): base + (i * 16) + 16]
        if len(entry) < 16:
            continue
        
        boot, chs1, ptype, chs2, start_lba, sectors = struct.unpack("<B3sB3sII", entry)
        if ptype != 0x00:
            print(f"Partition {i+1}: Type 0x{ptype:02X}, Start LBA = {start_lba}, Sectors = {sectors}, Offset (bytes) = {start_lba * SECTOR_SIZE}")
    
    signature = mbr[510:512].hex()
    print("Signature:", signature)
    print()

def check_gpt(f):
    hdr = read_sector(f, 1)
    if hdr[:8] == b"EFI PART":
        print("GPT Header detected at LBA 1.")
    else:
        print("No GPT header found.")
    print()

def main():
    try:
        with open(IMAGE_PATH, "rb") as img:
            first_sector = read_sector(img, 0)
            parse_mbr(first_sector)
            check_gpt(img)
    except FileNotFoundError:
        print("Could not find the disk image. Check the path in IMAGE_PATH.")
    except Exception as e:
        print("Error:", e)

if __name__ == "__main__":
    main()
