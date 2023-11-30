#!/usr/bin/perl
#
# read/display ELF header (x64) - by isra - https://hckng.org
#
# version 0.1 - november 2023:
#
#   * initial version
#

use strict;

# ELF header fields
my @e_keys = (
    'ei_mag0', 'ei_mag1', 'ei_mag2', 'ei_mag3', 'ei_class', 'ei_data', 
    'ei_version', 'ei_osabi', 'ei_abiversion', 'ei_pad1', 'ei_pad2',
    'ei_pad3', 'ei_pad4', 'ei_pad5', 'ei_pad6', 'ei_pad7',
    'e_type', 'e_machine', 'e_version', 'e_entry', 'e_phoff', 'e_shoff',
    'e_flags', 'e_ehsize', 'e_phentsize', 'e_phnum', 'e_shentsize', 'e_shnum',
    'e_shstrndx'
);

#
# data mappings
# based on https://github.com/lampmanyao/readelf/blob/master/readelf.pl
#

my %os_abis = (
    0x00 => 'System V', 0x01 => 'HP-UX', 0x02 => 'NetBSD', 0x03 => 'Linux',
    0x04 => 'GNU Hurd', 0x06 => 'Solaris', 0x07 => 'AIX', 0x08 => 'IRIX',
    0x09 => 'FreeBSD', 0x0A => 'Tru64', 0x0B => 'Novell Modesto',
    0x0C => 'OpenBSD', 0x0D => 'OpenVMS', 0x0E => 'NonStop Kernel',
    0x0F => 'AROS', 0x10 => 'Fenix OS', 0x11 => 'CloudABI', 0x53 => 'Sortix'
);

my @file_types = (
    'No file type', 'Relocatable', 'Executable', 'Shared object', 'Core'
);

my %machines = (
    0x0  => 'No specific instruction set', 0x02 => 'SPARC', 0x03 => 'x86',
    0x08 => 'MIPS', 0x14 => 'PowerPC', 0x16 => 'S390', 0x28 => 'ARM',
    0x2a => 'SuperH', 0x32 => 'IA-64', 0x3e => 'x86-64', 0xB7 => 'AArch64',
    0xF3 => 'RISC-Vn'
);


#
# parsing/display subroutines
#

# see https://refspecs.linuxfoundation.org/elf/gabi4+/ch4.eheader.html
sub parse_ehdr {
    my $fh = shift;

    read $fh, my $buff, 64;
    my @e = unpack("C a a a C12 S2 I q3 I S6", $buff);

    # create hash based on ELF header fields and unpacked values
    my %ehdr;
    for(my $i = 0; $i < @e_keys; $i++) {
        $ehdr{$e_keys[$i]} = $e[$i];
    }

    # check magic number
    if($e[0] != 0x7F && $e[1] !~ 'E' && $e[2] !~ 'L' && $e[3] !~ 'F') {
        die "Not an ELF file\n";
    }

    # check ei_class
    if($e[4] != 2) {
        die "Only ELF64 is supported\n";
    }

    return %ehdr;
}

# based on Linux's readelf output
sub display_ehdr {
    my %ehdr = @_;

    # format for ELF identification values
    my $f0 = "%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x ".
             "%02x %02x %02x %02x\n";

    # format for string values
    my $f1 = "  %-38s %s\n";
    my $f2 = "  %-38s %s (bytes)\n";

    # format for hexadecimal values
    my $f3 = "  %-38s 0x%x\n";

    
    print "\nELF header:\n";
    print "  Magic:  ";
    printf(
        $f0,
        $ehdr{'ei_mag0'}, unpack("C", $ehdr{'ei_mag1'}),
        unpack("C", $ehdr{'ei_mag2'}), unpack("C", $ehdr{'ei_mag3'}),
        $ehdr{'ei_class'}, $ehdr{'ei_data'}, 
        $ehdr{'ei_version'}, $ehdr{'ei_osabi'}, $ehdr{'ei_abiversion'},
        $ehdr{'ei_pad1'}, $ehdr{'ei_pad2'}, $ehdr{'ei_pad3'},
        $ehdr{'ei_pad4'}, $ehdr{'ei_pad5'}, $ehdr{'ei_pad6'},
        $ehdr{'ei_pad7'}
    );

    printf($f1, "Class:", "ELF64");
    
    if($ehdr{'ei_data'} == 1) {
        printf($f1, "Data:", "little-endian"); 
    } elsif($ehdr{'ei_data'} == 2) {
        printf($f1, "Data:", "big-endian"); 
    }
    
    printf($f1, "Version:", $ehdr{'ei_version'});
    printf($f1, "OS/ABI:", $os_abis{$ehdr{'ei_osabi'}});
    printf($f1, "ABI version:", $ehdr{'ei_abiversion'});
    printf($f1, "Type:", $file_types[$ehdr{'e_type'}]);
    printf($f1, "Machine:", $machines{$ehdr{'e_machine'}});
    printf($f3, "Version:", $ehdr{'e_version'});
    printf($f3, "Entry point address:", $ehdr{'e_entry'});
    printf($f1, "Start of program headers:", $ehdr{'e_phoff'});
    printf($f1, "Start of section headers:", $ehdr{'e_shoff'});
    printf($f3, "Options:", $ehdr{'e_flags'});
    printf($f2, "Size of this header:", $ehdr{'e_ehsize'});
    printf($f2, "Size of program headers:", $ehdr{'e_phentsize'});
    printf($f1, "Number of program headers:", $ehdr{'e_phnum'});
    printf($f2, "Size of section headers:", $ehdr{'e_shentsize'});
    printf($f1, "Number of section headers:", $ehdr{'e_shnum'});
    printf($f1, "Section header string table index:", $ehdr{'e_shstrndx'});
    print "\n";
}


#
# main code
#

my $elf = $ARGV[0] || undef;
print "\nUsage: perl ehdr.pl file\n\n" if(!$elf);
exit if(!$elf);
die "File $elf doesn't exist!\n" if(!-e $elf);
die "$elf not a file!\n" if(!-f $elf);

open my $fh, '<:raw', $elf or die "Couldn't open $elf\n";
my %ehdr = parse_ehdr($fh);
display_ehdr(%ehdr);
close $fh;