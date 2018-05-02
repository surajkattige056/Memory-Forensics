#Authors: Ahmed Alagili, Suraj S Kattige
#Course: CSE469

import hashlib
import sys

#This function is used to find the type of partitions of the file systems from the partition table
def type_of_partition(a):
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


#This function parses the partition table in the MBR
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
        nbr_sec_part4 = (byte_name[i]) #00
        i += 1
        nbr_sec_part = hex((((nbr_sec_part4 << 24) | nbr_sec_part3 << 16) | nbr_sec_part2 << 8) | nbr_sec_part1)

        start_sect_addr = int(nbr_sec_mbr, 16)
        size_of_partition = int(nbr_sec_part, 16)

        if((tof != 0) and (tof != "Error")):
            print("(%s) %s, %s, %s" %(code, tof, start_sect_addr, size_of_partition))

            if((code == "04") or (code == "06") or (code == "0B") or (code == "0C") or (code == "1B") or (code == "86")):
                fat_partition(code, byte_name, start_sect_addr, size_of_partition)
            print("\n")
            print("===============================================================")
    return 0


#This function parses the contents in VBR
def fat_partition(code, byte_name, start_sect_addr, size_of_partition):
    start_sect = 0 #Reserved area always starts at sector 0
    size = ((byte_name[start_sect_addr * 512 + 15] << 8 )| byte_name[start_sect_addr * 512 + 14])

    if (start_sect + size) < 1:
        end_sect = 0
    else:
        end_sect = start_sect + size - 1

    sect_per_cluster = byte_name[start_sect_addr * 512 + 13]
    no_of_fat = byte_name[start_sect_addr * 512 + 16]

    if ((code == "04") or (code == "06")  or (code == "86")):
        size_of_fat = ((byte_name[start_sect_addr * 512 + 23] << 8) | byte_name[start_sect_addr * 512 + 22])
    else:
        size_of_fat = ((((byte_name[start_sect_addr * 512 + 39] << 24) | (byte_name[start_sect_addr * 512 + 38] << 16)) | (byte_name[start_sect_addr * 512 + 37] << 8)) | (byte_name[start_sect_addr * 512 + 36]))

    if no_of_fat == 0: #If number of FATs is 0, Then FAT start and end sectors will be 0
        fat_start_sect = 0
        fat_end_sect = 0
    else:
        fat_start_sect = end_sect + 1 #FAT sector address starts after the reserved area. hence endsect + 1
        fat_end_sect = (size_of_fat * no_of_fat) + fat_start_sect - 1   #FAT end sector would be (number of fat * size of one FAT) + fat start sector address - 1

    if fat_end_sect == 0: #If there are no FAT files, then first sector of cluster 2 will be 0 as well
        first_sect_cluster = 0
    else:
        if ((code == "04") or (code == "06") or (code == "86")): #If it is a FAT 16 file type
            no_of_files_direct = ((byte_name[start_sect_addr * 512 + 18] << 8) | byte_name[start_sect_addr * 512 + 17]) #Number of files in the root directory
            bytes_per_sect = ((byte_name[start_sect_addr * 512 + 12] << 8) | byte_name[start_sect_addr * 512 + 11]) #bytes per sector in the file system
            no_of_files_sect = int(round(no_of_files_direct * 32/ bytes_per_sect))  #number of files in root directory in sectors
            first_sect_cluster = fat_end_sect + no_of_files_sect + start_sect_addr + 1    #First sector of cluster 2 will be fat end sector address + number of root directory files in sectors + 1
        else:   #If the file system is of type FAT 32
            first_sect_cluster = fat_end_sect + start_sect_addr + 1   #First sector of the cluster 2 will be end sector of FAT + 1

    print("Reserved area:\tStart sector: %s\tEnding sector: %s\tSize: %s" %(start_sect, end_sect, size))
    print("Sectors per cluster: %s sectors" %(sect_per_cluster))
    print("FAT area: \tStart sector: %s\tEnding sector: %s" %(fat_start_sect, fat_end_sect))
    print("# of FATs: %s" %(no_of_fat))
    print("The size of each FAT: %s sectors" %(size_of_fat))
    print("The first sector of cluster 2: %s sectors" %(first_sect_cluster))
    return 0


def main():
    # --------------------Requirement A---------------------#
    filename = open(sys.argv[1], "rb")

    #--------------------Requir1ement B---------------------#
    print("# --------------------Requirement B---------------------#")
    BUF_SIZE = 65536  # lets read stuff in 64kb chunks!

    md5 = hashlib.md5()
    sha1 = hashlib.sha1()

    with open(sys.argv[1], 'rb') as f:
        while True:
            data = f.read(BUF_SIZE)
            if not data:
                break
            md5.update(data)
            sha1.update(data)

    print("MD5: {0}".format(md5.hexdigest()))
    print("SHA1: {0}".format(sha1.hexdigest()))
    arr1 = sys.argv[1].split('\\')
    arr = arr1[len(arr1) - 1].split('.')
    file_md5 = "MD5-" + arr[0] + ".txt"
    file_sha1 = "SHA1-" + arr[0] + ".txt"

    #Writing the MD5 and SHA1 hash to files for the image.
    output_file_md5 = open(file_md5, "w")
    output_file_md5.write(md5.hexdigest())
    output_file_md5.close()

    output_file_sha1 = open(file_sha1, 'w')
    output_file_sha1.write(sha1.hexdigest())
    output_file_sha1.close()
    print("\n")
    # --------------------Requirement C---------------------#
    print("# --------------------Requirement C---------------------#")
    byte_name = filename.read()
    partition_table(byte_name)
    filename.close()
    return 0


main()