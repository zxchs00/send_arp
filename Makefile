send_arp: send_arp.c
	gcc -o send_arp send_arp.c -lpcap

clean:
	rm -f *.o
	rm -f send_arp
