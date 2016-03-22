# daft-dhcp-client

Small and stupid DHCP client written in C.
The only thing shared with the DHCP server is your MAC address.

#### Motivation
Study linux networking programming.

#### Installation
```bash
git clone --depth=1 https://github.com/anryko/daft-dhcp-clent.git
cd daft-dhcl-clent
make
```

#### Usage
```bash
./daft-dhcp-client -h
Usage: ./daft-dhcp-client -i <interface> [-d] [-r <ip>] [-q <ip>] [-h]

        -h --help                       This help message
        -i --interface <interface>      Interface name
        -d --discover                   Discover DHCP Server
        -r --request <ip>               Request IP lease
        -q --release <ip>               Release IP lease

$ sudo ./daft-dhcp-client -i eth0
Your-IP 10.0.2.16
Message-Type OFFER
Subnet-Mask 255.255.255.0
Default-Gateways 10.0.2.2
Domain-Name-Servers 10.0.2.3
Lease-Time 86400
Server-ID 10.0.2.2
$ sudo ./daft-dhcp-client -i eth0 -r 10.0.2.16
Your-IP 10.0.2.16
Message-Type ACK
Subnet-Mask 255.255.255.0
Default-Gateways 10.0.2.2
Domain-Name-Servers 10.0.2.3
Lease-Time 86400
Server-ID 10.0.2.2
$ sudo ./daft-dhcp-client -i eth0 -q 10.0.2.16
```

You can parse *stdout* and configure network interface accordingly.
