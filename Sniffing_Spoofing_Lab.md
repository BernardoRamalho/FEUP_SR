# Sniffing Spoofing Lab

## Lab Environment

The lab environment is composed of 3 machines. An attacker and 2 hosts. Each machine has her own docker container and all 3 containers should be running at the same time.

All the code is developed outside of the containers, in the 'volume' directory. This is a shared directory with the attacker's container, so all code developed there will appear in the attacker's container.

Address Table:
  - **Attacker:** 10.9.0.1
  - **Host A:** 10.9.0.5
  - **Host B:** 10.9.0.6
  
## Task 1: Using Scapy to Sniff and Spoof Packets

### Task 1.1: Sniffing Packets

Example code given:
``` 
#!/usr/bin/env python3
from scapy.all import *

# Define function that will be called each time a packet is sniffed
def print_pkt(pkt):
  pkt.show()
  
pkt = sniff(iface=’br-7ee80ff0c194’, filter=’icmp’, prn=print_pkt)
```

Scapy allows the sniffing of multiple network interfaces. For that, just enumerate all the networks in the 'iface' parameter as an array.

By changing the filter it is possible to curate the packets sniffed:
  - Capture only ICMP packets:
    - filter = 'icmp';
  - Capture any TCP packet that comes from a particular IP and with a destination port number 23:
    - filter = 'tcp and src host 10.9.0.5 and dst port 23' (10.9.0.5 is one the hosts in the network);
    - in order to test, run "telnet 10.9.0.5 23" in the other host machine.
  -  Capture packets comes from or to go to a particular subnet. You can pick any subnet, such as 128.230.0.0/16; you should not pick the subnet that your VM is attached to.
    - filter = 'net 128.230.0.0/16'
    - in order to test, ping an address belonging to that subnet, like '128.230.0.1'.
 
 ### Task 1.2: Spoofing ICMP Packets

In order to spoof an ICMP packet, the attacker must send an ICMP packet where the source is another machine. With the code bellow, Host B will think the ICMP packet came from 
Host A and will send an ICMP reply packet.

**ICMP Packet Spoofing code:**
```
from scapy.all import *

# Create and IP Object
a = IP()

# Change the Destination and the Source 
a.dst = '10.9.0.6'
a.src = '10.9.0.5'

# Create the ICMP Object
b = ICMP()

# Merge IP and ICMP in order to create an ICMP Packet
p = a/b

# Send the packet
send(p)
```

In order to test this code, use wireshark to check that Host A receives an ICMP reply packet without having sent an ICMP request packet.

### Task 1.3: Traceroute

For this task, it is only necessary to send ICMP request packets with incrementing Time-To-Live (TTL).
This tells the packet how many routers it can go thorught before being dropped by a router. The router that drops the packets sends back an error packet.
This way we can get all the routers by sending X ICMP request packets, each with a TTL increment.

**Traceroute code:**
```
from scapy.all import *

# Counter to keep increment the TTL
ttl = 1

# Create IP Object with the desired destination and the TTL
a = IP()
a.dst = '8.8.8.8'
a.ttl = ttl

# Create ICMP Request Object
b = ICMP()

# Send the packet and wait for a response
pkt = sr1(a/b)    # sr1 sends a packet and waits for a response

# Array to save the IPs
ips = []
ips.append(pkt.src)

# Loop until the packet reaches the desired destination
while pkt.src != '8.8.8.8':
	# Increment TTL
  ttl += 1
	a.ttl = ttl
  
  # Send the packet and wait for response
	pkt = sr1(a/b)	
  
  # Save IP address
	ips.append(pkt.src)

# Print the rounting in order
router_number = 1
print("----- ROUTERS -----")
for s in ips:
	print("Router " + str(router_number) + " IP: " + s)
	router_number += 1
```

### Task 1.4: Sniffing and-then Spoofing

In this task, it is necessary to combine both Task 1.1 and Task 1.2. First we must setup an ICMP packet sniffing. 
Then, if the packet is an ICMP request packet, reply to the source of that packet with and ICMP reply packet. 
In that packet the source must be changed to the destination of the ICMP request packet.
This way, the victim will think the IP that she is trying to contact is online even if it isn't.

**Sniffing and-then Spoofing code:**
```
#!/usr/bin/env python3
from scapy.all import *

def sniffSpoof(pkt):
  # Only spoof if it is a request packet
	if pkt[ICMP].type != 8:		# 8 is the code for a echo-request
		return
  
  # Swap the source and destination of the packet
	a = IP()
	a.dst = pkt[IP].src
	a.src = pkt[IP].dst
	 
  # Create an ICMP Reply object
	b = pkt[ICMP]
	b.type = 0			# 0 is the code for a echo-reply
	
	p = a/b
	
	send(p)

pkt = sniff(iface='br-7ee80ff0c194', filter='icmp', prn=sniffSpoof)

```

