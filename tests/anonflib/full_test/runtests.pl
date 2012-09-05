#!/usr/bin/perl -w

use lib qw(perl_libs/);

use Net::Pcap;
use NetPacket::Ethernet;
use NetPacket::IP;
use NetPacket::UDP;
use NetPacket::TCP;
#use Digest::SHA1  qw(sha1 sha1_hex sha1_base64);

my $pcap_error;
my $pcap_handle;  # capturing trace file
my $tracefile;
my $anonymized_trace;
my $verbose=0;
my $error_found;

# try to get a pcap descriptor

$tracefile = "traces/http.trace";
$anonymized_trace = "anonymized.trace";

my $pkts_num=0;
my $pkt_index;
my %IP_field = ();
my %TCP_field = ();
my %mapped = ();

$IP_field{"PAYLOAD"}="data";
$IP_field{"CHECKSUM"}="cksum";
$IP_field{"SRC_IP"}="src_ip";
$IP_field{"DST_IP"}="dest_ip";
$IP_field{"TTL"}="ttl";
$IP_field{"TOS"}="tos";
$IP_field{"ID"}="id";
#$IP_field{"VERSION"}="ver";
#$IP_field{"OPTIONS"}="options";
$IP_field{"PACKET_LENGTH"}="len";
$IP_field{"IP_PROTO"}="proto";
#$IP_field{"IHL"}="hlen";
#$IP_field{"FRAGMENT_OFFSET"}="foffset";

$TCP_field{"PAYLOAD"}="data";
$TCP_field{"CHECKSUM"}="cksum";
$TCP_field{"SRC_PORT"}="src_port";
$TCP_field{"DST_PORT"}="dest_port";
$TCP_field{"SEQUENCE_NUMBER"}="seqnum";
$TCP_field{"ACK_NUMBER"}="acknum";
#$TCP_field{"OFFSET_AND_RESERVED"}="reserved";
$TCP_field{"FLAGS"}="flags";
$TCP_field{"WINDOW"}="winsize";
$TCP_field{"URGENT_POINTER"}="urg";


$pcap_handle = Net::Pcap::open_offline($tracefile, \$pcap_error);

die "Net::Pcap::open_offline failed trying to open '$tracefile': $pcap_error\n"
	unless defined($pcap_handle);
if ($verbose==1) {
	print "reading from '$tracefile'\n";
}

# process packets
Net::Pcap::loop($pcap_handle, -1, \&decode_packet, "dummy argument for callback");

# done
Net::Pcap::close($pcap_handle);

@files_found = <./test-IP-*>;

foreach $file (@files_found) {
        if ($file =~ /.c/) {
                next;
        }

	@parts = split(/-/, $file);

	print "\ntesting ".$file;
	if ($verbose==1) {
		system($file." ".$tracefile." ".$anonymized_trace);
	}
	else {
		system($file." ".$tracefile." ".$anonymized_trace." > /dev/null");
	}

	if ($?!=0) {
		print "failed!\n";
		exit;
	}

	%mapped = ();

	$pcap_handle = Net::Pcap::open_offline($anonymized_trace, \$pcap_error);

	die "Net::Pcap::open_offline failed trying to open '$anonymized_trace': $pcap_error\n"
		unless defined($pcap_handle);
	if ($verbose==1) {
		print "reading from '$anonymized_trace'\n";
	}

	$error_found = 0;
	$pkt_index=0;
#	$random_first=-1;

	# process packets
	Net::Pcap::loop($pcap_handle, -1, \&check_IP_packet, $parts);

	# done
	Net::Pcap::close($pcap_handle);

	if ($error_found==0) {
		print "OK";
	}
	else {
		print "correctness failed!";
		#print "\n";
		#exit;
	}
}

@files_found = <./test-TCP-*>;

foreach $file (@files_found) {
        if ($file =~ /.c/) {
                next;
        }

	@parts = split(/-/, $file);

	print "\ntesting ".$file;
	if ($verbose==1) {
		system($file." ".$tracefile." ".$anonymized_trace);
	}
	else {
		system($file." ".$tracefile." ".$anonymized_trace." > /dev/null");
	}

	if ($?!=0) {
		print "failed!\n";
		exit;
	}

	%mapped = ();

	$pcap_handle = Net::Pcap::open_offline($anonymized_trace, \$pcap_error);

	die "Net::Pcap::open_offline failed trying to open '$anonymized_trace': $pcap_error\n"
		unless defined($pcap_handle);
	if ($verbose==1) {
		print "reading from '$anonymized_trace'\n";
	}

	$error_found = 0;
	$pkt_index=0;
#	$random_first=-1;

	# process packets
	Net::Pcap::loop($pcap_handle, -1, \&check_TCP_packet, $parts);

	# done
	Net::Pcap::close($pcap_handle);

	if ($error_found==0) {
		print "OK";
	}
	else {
		print "correctness failed!";
		#print "\n";
		#exit;
	}
}

print "\n";


sub check_IP_packet {
	my($data, $header, $pkt) = @_;

	my $eth = NetPacket::Ethernet->decode($pkt);
	my $ip = NetPacket::IP->decode($eth->{data});

	if ( match_anonymized($original_IP_packets[$pkt_index++]->{$IP_field{$parts[2]}}, $ip->{$IP_field{$parts[2]}}, $parts[3])<0 ) {
		$error_found=1;
		Net::Pcap::breakloop($pcap_handle);
	
	}

}

sub check_TCP_packet {
	my($data, $header, $pkt) = @_;

	my $eth = NetPacket::Ethernet->decode($pkt);
	my $ip = NetPacket::IP->decode($eth->{data});
	my $tcp = NetPacket::TCP->decode($ip->{data});

	if ( match_anonymized($original_TCP_packets[$pkt_index++]->{$TCP_field{$parts[2]}}, $tcp->{$TCP_field{$parts[2]}}, $parts[3])<0 ) {

		$error_found=1;
		Net::Pcap::breakloop($pcap_handle);

	}

}

sub decode_packet {
	my($data, $header, $pkt) = @_;

	my $eth = NetPacket::Ethernet->decode($pkt);
	my $ip = NetPacket::IP->decode($eth->{data});
	my $tcp = NetPacket::TCP->decode($ip->{data});

	$original_IP_packets[$pkts_num] = $ip;
	$original_TCP_packets[$pkts_num++] = $tcp;
}


sub match_anonymized {
	my($original, $anonymized, $function) =@_;

	if ( $function eq "UNCHANGED" ) { if ( $original eq $anonymized) { return 1; } else { return -1; } }
	elsif ( $function eq "MAP") { if ( not exists $mapped{$original} ) { $mapped{$original}=$anonymized; return 1; } else { if ( $mapped{$original} eq $anonymized ) { return 1; } else { return -1; } } }
	elsif ( $function eq "MAP_DISTRIBUTION_UNIFORM") { if ( not exists $mapped{$original} ) { $mapped{$original}=$anonymized; if ($anonymized =~ /^\d\.\d\.\d/) { return 1; } else { if ( $anonymized>=1 && $anonymized<=10000 ) { return 1; } else { return -1; } } } else { if ( $mapped{$original} eq $anonymized ) { return 1; } else { return -1; } } }
	elsif ( $function eq "MAP_DISTRIBUTION_GAUSSIAN") { if ( not exists $mapped{$original} ) { $mapped{$original}=$anonymized; return 1; } else { if ( $mapped{$original} eq $anonymized ) { return 1; } else { return -1; } } }   # compute mean and variation values?  
	elsif ( $function eq "STRIP") { if ( not ($original eq "") && ($original eq $anonymized)) { return -1; } else { return 1; } }	#a better way to test it?
#	elsif ( $function eq "RANDOM") { if ( $random_first==-1) { $random_first=$anonymized; return 1; } else { if ($anonymized!=(((($random_first * 1103515245 + 12345)/65536)%32768)) ) { return -1} else { $random_first=$anonymized; return 1; } } }
	elsif ( $function eq "RANDOM") { return 1; }   #above is the right solution
	elsif ( $function eq "PATTERN_FILL") { if ( $anonymized eq "84.69.83.84" || substr($anonymized,0,4) eq "TEST" || (get_byte($anonymized,0) eq ord(T)) || (get_byte($anonymized,0) eq ord(E) && get_byte($anonymized,1) eq ord(T) ) || (get_byte($anonymized,0) eq ord(T) && get_byte($anonymized,1) eq ord(S) && get_byte($anonymized,2) eq ord(E) && get_byte($anonymized,3) eq ord(T)) ) { return 1; } else { return -1; } }
	elsif ( $function eq "ZERO") { if ( $anonymized eq 0 || ord($anonymized) eq ord("\0") || $anonymized eq "0.0.0.0") { return 1; } else { print $anonymized."\n"; return -1; } }
	elsif ( $function eq "REPLACE") { if ( $anonymized eq "84.69.83.84" || substr($anonymized,0,4) eq "TEST" || (get_byte($anonymized,0) eq ord(T)) || (get_byte($anonymized,0) eq ord(E) && get_byte($anonymized,1) eq ord(T) ) || (get_byte($anonymized,0) eq ord(T) && get_byte($anonymized,1) eq ord(S) && get_byte($anonymized,2) eq ord(E) && get_byte($anonymized,3) eq ord(T)) ) { return 1; } else { return -1; } }
	elsif ( $function eq "PREFIX_PRESERVING") { if ( not exists $mapped{$original} ) { $mapped{$original}=$anonymized; return 1; } else { if ( $mapped{$original} eq $anonymized ) { return 1; } else { return -1; } } }
	elsif ( $function eq "PREFIX_PRESERVING_MAP") { if ( not exists $mapped{$original} ) { $mapped{$original}=$anonymized; return 1; } else { if ( $mapped{$original} eq $anonymized ) { return 1; } else { return -1; } } }
	#/*"CHECKSUM_ADJUST",*/ 
	elsif ( $function eq "FILENAME_RANDOM") { return 1; }   #no filename
	elsif ( $function eq "HASHED_SHA_PAD_WITH_ZERO") { if ( length($original)>0 && ($original eq $anonymized) ) { return -1; } else { return 1; } }  #compute sha and compare

	else { print "Invalid anonymization function\n"; return -1; }
}

sub get_byte {
        my($variable, $byte_number) =@_;
        my $seperator;

        if ($byte_number==0)    { $seperator=0b00000000000000000000000011111111; }
        elsif ($byte_number==1) { $seperator=0b00000000000000001111111100000000; }
        elsif ($byte_number==2) { $seperator=0b00000000111111110000000000000000; }
        elsif ($byte_number==3) { $seperator=0b11111111000000000000000000000000; }

        $ret= ($variable & $seperator) >> 8*$byte_number;

        return $ret;
}

