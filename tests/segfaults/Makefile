tests:
	rm -rf tmp && mkdir tmp
	./packet-size.prepare tmp/size.pcap
	md5sum tmp/size.pcap
	../../pcapsipdump -r tmp/size.pcap -d tmp
	rm -rf tmp
