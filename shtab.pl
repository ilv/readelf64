#!/usr/bin/perl
#
# read/display ELF section header table (x64) - by isra - https://hckng.org
#
# version 0.1 - november 2023:
#
#   * initial version
#
# reference: https://github.com/lampmanyao/readelf/blob/master/readelf.pl 
#

use strict;


# ELF header keys
my @e_keys = (
    'ei_mag0', 'ei_mag1', 'ei_mag2', 'ei_mag3', 'ei_class', 'ei_data', 
    'ei_version', 'ei_osabi', 'ei_abiversion', 'ei_pad1', 'ei_pad2',
    'ei_pad3', 'ei_pad4', 'ei_pad5', 'ei_pad6', 'ei_pad7',
    'e_type', 'e_machine', 'e_version', 'e_entry', 'e_phoff', 'e_shoff',
    'e_flags', 'e_ehsize', 'e_phentsize', 'e_phnum', 'e_shentsize', 'e_shnum',
    'e_shstrndx'
);

# section header keys
my @sh_keys = (
    'sh_name', 'sh_type', 'sh_flags', 'sh_addr', 'sh_offset', 'sh_size',
    'sh_link', 'sh_info', 'sh_addralign', 'sh_entsize'
);

# string table
my %strtab;

#
# data mappings, based on [1]
#

my %shtypes = (
    0 => 'NULL', 1 => 'PROGBITS', 2 => 'SYMTAB', 3 => 'STRTAB', 4 => 'RELA',
    5 => 'HASH', 6 => 'DYNAMIC', 7 => 'NOTE', 8 => 'NOBITS', 9 => 'REL',
    10 => 'SHLIB', 11 => 'DYNSYM', 14 => 'INIT_ARRAY', 15 => 'FINI_ARRAY',
    16 => 'PREINIT_ARRAY', 17 => 'GROUP', 18 => 'SYMTAB_SHNDX',
    0x60000000 => 'LOOS', 0x6ffffff5 => 'GNU_ATTRIBUTES',
    0x6ffffff6 => 'GNU_HASH', 0x6ffffffd => 'GNU_verdef',
    0x6ffffffe => 'GNU_verneed', 0x6fffffff => 'GNU_versym',
    0x6fffffff => 'HIOS', 0x70000000 => 'LOPROC',
    0x70000001 => 'X86_64_UNWIND', 0x7fffffff => 'HIPROC',
    0x80000000 => 'LOUSER', 0xffffffff => 'HIUSER'
);

my %shflags = (
    0x0 => '0', 0x1 => 'W', 0x2 => 'A', 0x3 => 'WA', 0x4 => 'X', 0x6 => 'AX',
    0x10 => 'M', 0x20 => 'S', 0x30 => 'MS', 0x40 => 'I', 0x42 => 'AI',
    0x80 => 'L', 0x100 => 'o', 0x200 => 'G', 0x400 => 'T', 0x403 => 'WAT',
    0x800 => 'SHF_COMPRESSED', 0x80000000 => 'E', 0x0ff00000 => 'SHF_MASKOS',
    0xf0000000 => 'p', 0x10000000 => 'l'
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

# see https://refspecs.linuxbase.org/elf/gabi4+/ch4.sheader.html
sub parse_shtab {
    my $fh      = shift;
    my %ehdr    = @_;

    # section header table
    my @shtab;

    seek $fh, $ehdr{'e_shoff'}, 0; 
    for (my $i = 0; $i < $ehdr{'e_shnum'}; $i++) {
        
        read $fh, my $buff, $ehdr{'e_shentsize'};
        my @s = unpack("I2 q4 I2 q2", $buff);

        # create entry based on section header fields and unpacked values
        my %shdr;
        for(my $i = 0; $i < @sh_keys; $i++) {
            $shdr{$sh_keys[$i]} = $s[$i];
        }
        push @shtab, \%shdr;

        # read content (strings) when entry of type 'STRTAB' = 3 is found
        if($shdr{'sh_type'} == 3) {
            my $tmpstr;
            my $curr_offset = tell $fh;
            seek $fh, $shdr{'sh_offset'}, 0;
            read $fh, $tmpstr, $shdr{'sh_size'};
            seek $fh, $curr_offset, 0;
            $strtab{$shdr{'sh_offset'}} = $tmpstr;
        }
    }

    return @shtab;
}

# get section name
sub secname {
    my $ndx = shift;
    my $str = shift;

    my $s = substr($str, $ndx);
    my $r = substr($s, 0, index($s, "\0"));
}

# get section names from string table
# must be performed after parsing the section header table
sub parse_secnames {
    my $ehdr    = shift;
    my $shtab   = shift;

    my $shstrtab = $shtab->[$ehdr->{'e_shstrndx'}];
    for(my $i = 0; $i < $ehdr->{'e_shnum'}; $i++) {
        my $name = secname(
            $shtab->[$i]{'sh_name'}, 
            $strtab{$shstrtab->{'sh_offset'}}
        );
        # add 'name' to each section header entry
        $shtab->[$i]{'name'} = $name;
    }
}

# based on Linux's readelf output and [1]
sub display_shtab {
    my $ehdr    = shift;
    my $shtab   = shift;

    printf(
        "\nThere are %d section headers, starting at offset 0x%x\n", 
        $ehdr->{'e_shnum'}, $ehdr->{'e_shoff'}
    );
    print "\nSection headers:\n",
          "[Nr]   Name                Type          Address    Offset     Size       EntSize    Flags  Link  Info  Align\n";

    for(my $i = 0; $i < @{$shtab}; $i++) {
        printf "[%03d] %-20s %-12s  0x%06x   0x%06x   0x%06x   0x%06x   %-4s   %-4d  %-4d  %-4d\n",
            $i,
            $shtab->[$i]{'name'},
            $shtypes{$shtab->[$i]{'sh_type'}},
            $shtab->[$i]{'sh_addr'},
            $shtab->[$i]{'sh_offset'},
            $shtab->[$i]{'sh_size'},
            $shtab->[$i]{'sh_entsize'},
            $shflags{$shtab->[$i]{'sh_flags'}},
            $shtab->[$i]{'sh_link'},
            $shtab->[$i]{'sh_info'},
            $shtab->[$i]{'sh_addralign'};
    }

    print "\nKey to Flags:\n".
          " W (write), A (alloc), X (execute), M (merge), S (strings), ".
          "l (large)\n I (info), L (link order), G (group), T (TLS), E ".
          "(exclude), x (unknown)\n O (extra OS processing required) o ".
          "(OS specific), p (processor specific)\n\n";
}


#
# main code
#

my $elf = $ARGV[0] || undef;
print "\nUsage: perl shtab.pl file\n\n" if(!$elf);
exit if(!$elf);
die "File $elf doesn't exist!\n" if(!-e $elf);
die "$elf not a file!\n" if(!-f $elf);

open my $fh, '<:raw', $elf or die "Couldn't open $elf\n";
my %ehdr = parse_ehdr($fh);
my @shtab = parse_shtab($fh, %ehdr);
parse_secnames(\%ehdr, \@shtab);
display_shtab(\%ehdr, \@shtab);