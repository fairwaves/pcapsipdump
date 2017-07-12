pcapsipdump version 0.2-trunk

Usage: pcapsipdump [-fpUt] [-i <interface> | -r <file>] [-d <working directory>]
                   [-v level] [-R filter] [-n filter] [-l filter] [-B size]
                   [expression]
 -f   Do not fork or detach from controlling terminal.
 -p   Do not put the interface into promiscuous mode.
 -U   Make .pcap files writing 'packet-buffered' - slower method,
      but you can use partitially written file anytime, it will be consistent.
 -i   Specify network interface name (i.e. eth0, em1, ppp0, etc).
 -r   Read from .pcap file instead of network interface.
 -d   Set directory, where captured files will be stored.
 -v   Set verbosity level (higher is more verbose).
 -B   Set the operating system capture buffer size, a.k.a. ring buffer size.
      This can be expressed in bytes/KB(*1000)/KiB(*1024)/MB/MiB/GB/GiB. ex.: '-B 64MiB'
      Set this to few MiB or more to avoid packets dropped by kernel.
 -R   RTP filter. Specifies what kind of RTP information to include in capture:
      'rtp+rtcp' (default), 'rtp', 'rtpevent', 't38', or 'none'.
 -n   Number-filter. Only calls to/from specified number will be recorded
      Argument is a regular expression. See 'man 7 regex' for details.
 -l   Record only each N-th call (i.e. '-l 3' = record only each third call)
 For the expression syntax, see 'man 7 pcap-filter'


pcapsipdump is a tool for dumping SIP sessions (+RTP
traffic, if available) to disk in a fashion similar
to "tcpdump -w" (format is exactly the same), but one
file per sip session (even if there is thousands of
concurrent SIP sessions).

pcapsipdump can also be used to split "bulk" pcap file
into bunch of individual files (one per call):
pcapsipdump -r <bulkfile> -d <dir-for-bunch-of-files>

for Red Hat/CentOS/Fedora rpm instructions see redhat/ dir
for Debian-specific instructions, see debian/ dir
