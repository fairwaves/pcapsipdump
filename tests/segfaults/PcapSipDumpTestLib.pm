#!/usr/bin/perl -w

package PcapSipDumpTestLib;

use strict;
use warnings;
use Exporter;
use base 'Exporter';
use List::Util qw[min max];

our @EXPORT = qw( $DLT_EN10MB pcap_create simple_write_packet make_mac_header make_ip_udp_header pcap_write_packet );
our $DLT_EN10MB=1;
our $pcap_time;
our $pcap_snaplen;

1;

sub pcap_create {
  my ($dlt,$fn,$snaplen)=@_;
  my $F;
  open($F,">$fn");
  print $F pack "I",0xa1b2c3d4; # uint32 magic_number
  print $F pack "S",2;          # uint16 version_major
  print $F pack "S",4;          # uint16 version_minor
  print $F pack "i",0;          # int32  GMT to local correction
  print $F pack "I",0;          # uint32 accuracy of timestamps
  print $F pack "I",$snaplen;   # uint32 snaplen
  print $F pack "I",$dlt;       # uint32 data link type
  $pcap_time=time;
  $pcap_snaplen=$snaplen;
  return $F;
}

sub simple_write_packet {
  my ($F,$data)=@_;
  pcap_write_packet($F,
    make_mac_header("0c1111111111","0c2222222222").
    make_ip_udp_header("192.168.1.1","192.168.2.2",5060,5060,length($data)),
    $data,0.01);
}

sub make_mac_header {
  my ($src_mac,$dst_mac)=@_;
  return pack "H*H*S",$dst_mac,$src_mac,8;
}

sub make_ip_udp_header {
  my ($src_ip,$dst_ip,$src_port,$dst_port,$udplength)=@_;
  my $ip_checksum=calculate_checksum(pack "CCnSSCCSC4C4",0x45,0,$udplength+28,0,0,64,17,0,split('\.',$src_ip),split('\.',$dst_ip));
  my $udp_checksum=calculate_checksum("n4",$src_port,$dst_port,$udplength+8,0);
  return
    (pack "CCnSSCCSC4C4",0x45,0,$udplength+28,0,0,64,17,$ip_checksum,split('\.',$src_ip),split('\.',$dst_ip)). #IP
    (pack "n4",$src_port,$dst_port,$udplength+8,$udp_checksum); #UDP
}

sub calculate_checksum {
  my ($msg) = @_;
  my ($len_msg,$num_short,$short,$chk);
  $len_msg = length($msg);
  $num_short = $len_msg / 2;
  $chk = 0;
  foreach $short (unpack("S$num_short", $msg)) {
    $chk += $short;
  }
  $chk += unpack("C", substr($msg, $len_msg - 1, 1)) if $len_msg % 2;
  $chk = ($chk >> 16) + ($chk & 0xffff);
  return(~(($chk >> 16) + $chk) & 0xffff);
}


sub pcap_write_packet {
  my ($F,$header,$data,$delay)=@_;
  my $hdlen=length($header)+length($data);
  $pcap_time+=$delay;
  print $F pack "I",$pcap_time;               # uint32 timestamp seconds
  print $F pack "I",(1e6*$pcap_time%1e6);     # uint32 timestamp microseconds
  print $F pack "I",min($hdlen,$pcap_snaplen);# uint32 number of octets of packet saved in file
  print $F pack "I",$hdlen;                   # uint32 actual length of packet
  print $F $header;
  print $F $data;
}
