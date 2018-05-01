import hashlib
import sys


def type_of_partition(a):
    output = ""
    code = "0"
    if(a == 0x01):
        output = "DOS 12-bit FAT"
        code = "01"
    elif(a == 0x04):
        output = "DOS 16-bit FAT for partitions smaller than 32 MB"
        code = "04"
    elif (a == 0x05):
        output = "Extended partition"
        code = "05"
    elif (a == 0x06):
        output = "DOS 16-bit FAT for partitions larger than 32 MB"
        code = "06"
    elif (a == 0x07):
        output = "NTFS"
        code = "07"
    elif (a == 0x08):
        output = "AIX bootable partition"
        code = "08"
    elif (a == 0x09):
        output = "AIX data partition"
        code = "09"
    elif (a == 0x0b):
        output = "DOS 32-bit FAT"
        code = "0B"
    elif (a == 0x0c):
        output = "DOS 32-bit FAT for interrupt 13 support"
        code = "0C"
    elif (a == 0x17):
        output = "Hidden NTFS partition (XP and earlier)"
        code = "17"
    elif (a == 0x1b):
        output = "Hidden FAT32 partition"
        code = "1B"
    elif (a == 0x1e):
        output = "Hidden VFAT partition"
        code = "1E"
    elif (a == 0x3c):
        output = "Partition Magic recovery partition"
        code = "3C"
    elif ((a == 0x66) or (a == 67) or (a == 68) or (a == 69)):
        output = "Novell partitions"
        if(a == 0x66):
            code = "66"
        elif(a == 0x67):
            code = "67"
        elif(a == 0x68):
            code = "68"
        else:
            code = "69"
    elif (a == 0x81):
        output = "Linux"
        code = "81"
    elif (a == 0x82):
        output = "Linux swap partition (can also be associated with Solaris partitions)"
        code = "82"
    elif (a == 0x83):
        output = "Linux native file systems (Ext2, Ext3, Reiser, xiafs)"
        code = "83"
    elif (a == 0x86):
        output = "FAT 16 volume/stripe set (Windows NT)"
        code = "86"
    elif (a == 0x87):
        output = "High Performance File System (HPFS) fault-tolerant mirrored partition or NTFS volume/stripe set"
        code = "87"
    elif (a == 0xa5):
        output = "FreeBSD and BSD/386"
        code = "A5"
    elif (a == 0xa6):
        output = "OpenBSD"
        code = "A6"
    elif (a == 0xa9):
        output = "NetBSD"
        code = "A9"
    elif (a == 0xc7):
        output = "Typical of a corrupted NTFS volume/stripe set"
        code = "C7"
    elif (a == 0xeb):
        output = "BeOS"
        code = "EB"
    else:
        if(a == 0x00):
            output = 0
            code = 0
        else:
            output = "Error"
            code = 99
    return output, code

def partition_table(byte_name):
    i = 446
    while i < 510:
        current_state = hex(byte_name[i]) #00
        i += 1  #447
        beg_partition_head = hex(byte_name[i]) #01
        i += 1  #448
        beg_partition_cyl_sec1 = (byte_name[i]) #01
        i += 1  #449
        beg_partition_cyl_sec2 = (byte_name[i]) #00
        beg_partition_cyl_sec = hex( ((beg_partition_cyl_sec2) << 8) | (beg_partition_cyl_sec1))
        i += 1  #450
        tof, code = type_of_partition((byte_name[i])) #07
        i += 1  #451
        end_partition_head = (byte_name[i]) #fe
        i += 1  #452
        end_partition_cyl_sec1 = (byte_name[i]) #3f
        i += 1  #453
        end_partition_cyl_sec2 = (byte_name[i]) #7f
        end_partition_cyl_sec = hex((end_partition_cyl_sec2 << 8) | end_partition_cyl_sec1)
        i += 1  #454
        nbr_sec_mbr1 = (byte_name[i]) #3f
        i += 1  #455
        nbr_sec_mbr2 = (byte_name[i]) #00
        i += 1  #456
        nbr_sec_mbr3 = (byte_name[i]) #00
        i += 1  #457
        nbr_sec_mbr4 = (byte_name[i]) #00
        nbr_sec_mbr = hex((((nbr_sec_mbr4 << 24) | nbr_sec_mbr3 << 16) | nbr_sec_mbr2 << 8) | nbr_sec_mbr1)
        i += 1  #458
        nbr_sec_part1 = (byte_name[i]) #41
        i += 1  #459
        nbr_sec_part2 = (byte_name[i]) #60
        i += 1  #460
        nbr_sec_part3 = (byte_name[i])#1f
        i += 1  #461
        # print("value of i at the end: %s" %i)
        nbr_sec_part4 = (byte_name[i]) #00
        i += 1
        nbr_sec_part = hex((((nbr_sec_part4 << 24) | nbr_sec_part3 << 16) | nbr_sec_part2 << 8) | nbr_sec_part1)

        start_sect_addr = int(nbr_sec_mbr, 16) #TODO: Add the calculation part
        size_of_partition = int(nbr_sec_part, 16) #TODO: Add the calculation part
        if((tof != 0) and (tof != "Error")):
            print("(%s) %s, %s, %s" %(code, tof, start_sect_addr, size_of_partition))
            if((code == "04") or (code == "06") or (code == "0B") or (code == "0C") or (code == "1B") or (code == "86")):
                fat_partition(code, byte_name, start_sect_addr, size_of_partition)

            print("\n")
    return 0

def fat_partition(code, byte_name, start_sect_addr, size_of_partition):
    start_sect = 0
    size = ((byte_name[start_sect_addr + 15] << 8 )| byte_name[start_sect_addr + 14])
    if (start_sect + size) < 1:
        end_sect = 0
    else:
        end_sect = start_sect + size - 1
    sect_per_cluster = byte_name[start_sect_addr + 13]
    fat_area = 0
    no_of_fat = byte_name[start_sect_addr + 16]
    if ((code == "04") or (code == "06")  or (code == "86")):
        size_of_fat = ((byte_name[start_sect_addr + 23] << 8) | byte_name[start_sect_addr + 22])
    else:
        size_of_fat = ((((byte_name[start_sect_addr + 35] << 24) | (byte_name[start_sect_addr + 34] << 16)) | (byte_name[start_sect_addr + 33] << 8)) | (byte_name[start_sect_addr + 32]))
    if no_of_fat == 0:
        fat_start_sect = 0
        fat_end_sect = 0
    else:
        fat_start_sect = end_sect + 1
        fat_end_sect = (size_of_fat * no_of_fat) + fat_start_sect - 1
    if fat_end_sect == 0:
        first_sect_cluster = 0
    else:
        if ((code == "04") or (code == "06") or (code == "86")):
            no_of_files_direct = ((byte_name[start_sect_addr + 18] << 8) | byte_name[start_sect_addr + 17])
            bytes_per_sect = ((byte_name[start_sect_addr + 12] << 8) | byte_name[start_sect_addr + 11])
            no_of_files_sect = no_of_files_direct / bytes_per_sect
            first_sect_cluster = fat_end_sect + no_of_files_sect - 1
        else:
            first_sect_cluster = fat_end_sect + 1

    print("Reserved area:\tStart sector: %s\tEnding sector: %s\tSize: %s" %(start_sect, end_sect, size))
    print("Sectors per cluster: %s sectors" %(sect_per_cluster))
    print("FAT area: %s\tStart sector: %s\tEnding sector: %s" %(fat_area, fat_start_sect, fat_end_sect))
    print("# of FATs: %s" %(no_of_fat))
    print("The size of each FAT: %s sectors" %(size_of_fat))
    print("The first sector of cluster 2: %s sectors" %(first_sect_cluster))
    return 0

def main():
    # --------------------Requirement 1---------------------#
    filename = open(sys.argv[1], "rb")

    #--------------------Requirement 2---------------------#
    print("# --------------------Requirement 2---------------------#")
    BUF_SIZE = 65536  # lets read stuff in 64kb chunks!

    md5 = hashlib.md5()
    sha1 = hashlib.sha1()

    # with open(sys.argv[1], 'rb') as f:
    with open(sys.argv[1], 'rb') as f:
        while True:
            data = f.read(BUF_SIZE)
            if not data:
                break
            md5.update(data)
            sha1.update(data)

    print("MD5: {0}".format(md5.hexdigest()))
    print("SHA1: {0}".format(sha1.hexdigest()))

    print("\n")
    # --------------------Requirement 3---------------------#
    print("# --------------------Requirement 3---------------------#")
    byte_name = filename.read()
    # print("Type of partition: %s " %hex(byte_name[450]))
    partition_table(byte_name)

    return 0




main()