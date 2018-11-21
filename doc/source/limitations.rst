===========
Limitations
===========

Subnets created before Kilo can have their DHCP server's IP in the middle of
an allocation pool. This causes the first VMs to be allocated the first
free IP addresses of a pool, for example, with a pool starting at 10.0.0.2 :

 - 10.0.0.2 : vm1
 - 10.0.0.3 : vm2
 - 10.0.0.4 : DHCP server
 - 10.0.0.5 : vm3

When this stack is imported in Heat, the DHCP server IP is set to the lowest
free IP address of its pool. Depending on the VM creation order, the DHCP
address can either collide with vm1's or vm2's IP.
