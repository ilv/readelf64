#!/usr/bin/perl
#
# read/display ELF program header table (x64) - by isra - https://hckng.org
#
# version 0.1 - november 2023:
#
#   * initial version
#
# reference: https://github.com/lampmanyao/readelf/blob/master/readelf.pl 
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

# program header fields
my @p_keys = (
    'p_type', 'p_flags', 'p_offset', 'p_vaddr', 'p_paddr', 'p_filesz',
    'p_memsz', 'p_align'
);


#
# data mappings, based on [1]
#

my @file_types = (
    'No file type', 'Relocatable', 'Executable', 'Shared object', 'Core'
);

my %ph_types = (
    0x00000000 => 'NULL', 0x00000001 => 'LOAD', 0x00000002 => 'DYNAMIC',
    0x00000003 => 'INTERP', 0x00000004 => 'NOTE', 0x00000005 => 'SHLIB',
    0x00000006 => 'PHDR', 0x60000000 => 'LOOS', 0x6474e550 => 'GNU_EH_FRAME',
    0x6474e551 => 'GNU_STACK', 0x6474e552 => 'GNU_RELRO', 0x6FFFFFFF => 'HIOS',
    0x70000000 => 'LOPROC', 0x7FFFFFFF => 'HIPROC'
);

my %ph_flags = (
    1 => '  E', 2 => ' W ', 3 => ' WE', 4 => 'R  ', 5 => 'R E', 6 => 'RW '
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

# see https://refspecs.linuxbase.org/elf/gabi4+/ch5.pheader.html
sub parse_phtab {
    my $fh      = shift;
    my %ehdr    = @_;

    # program header table
    my @phtab;

    seek $fh, $ehdr{'e_phoff'}, 0; 
    for (my $i = 0; $i < $ehdr{'e_phnum'}; $i++) {
        
        read $fh, my $buff, $ehdr{'e_phentsize'};
        my @p = unpack("I2 q6", $buff);

        # create entry based on program header fields and unpacked values
        my %phdr;
        for(my $i = 0; $i < @p_keys; $i++) {
            $phdr{$p_keys[$i]} = $p[$i];
        }
        push @phtab, \%phdr;
    }

    return @phtab;
}

# based on Linux's readelf output and [1]
sub display_phtab {
    my $ehdr    = shift;
    my $phtab   = shift;

    die "\nNo program headers found\n\n" if(!$ehdr->{'e_phnum'});

    print "\nFile type is $file_types[$ehdr->{'e_type'}]\n";
    printf("Entry point 0x%x\n", $ehdr->{'e_entry'});
    print "There are $ehdr->{'e_phnum'} program headers, starting at offset ";
    print "$ehdr->{'e_phoff'}\n";
    print "\nProgram headers:\n";
    printf(
        " %-12s %-10s %-10s %-10s %-10s %-10s %-06s %-10s\n", 
        "Type", "Offset", "VirtAddr", "PhysAddr", "FileSize", "MemSize",
        "Flags", "Align"
    );

    my $t = " %-12s 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%-04s 0x%08x\n";
    for (my $i = 0; $i < $ehdr->{'e_phnum'}; $i++) {
        if (exists $ph_types{$phtab->[$i]{'p_type'}}) {
            printf(
                $t,
                $ph_types{$phtab->[$i]{'p_type'}},
                $phtab->[$i]{'p_offset'},
                $phtab->[$i]{'p_vaddr'},
                $phtab->[$i]{'p_paddr'},
                $phtab->[$i]{'p_filesz'},
                $phtab->[$i]{'p_memsz'},
                $ph_flags{$phtab->[$i]{'p_flags'}},
                $phtab->[$i]{'p_align'}
            );
        }
    }
    print "\n";
}

#
# main code
#

my $elf = $ARGV[0] || undef;
print "\nUsage: perl phtab.pl file\n\n" if(!$elf);
exit if(!$elf);
die "File $elf doesn't exist!\n" if(!-e $elf);
die "$elf not a file!\n" if(!-f $elf);

open my $fh, '<:raw', $elf or die "Couldn't open $elf\n";
my %ehdr = parse_ehdr($fh);
my @phtab = parse_phtab($fh, %ehdr);
display_phtab(\%ehdr, \@phtab);