BGP Support is being placed into the thrasher product. This will include 
a new handshake type that will include authentication for both injections
and removes. 

At the moment the compile is a bit hacky - I actually have a dependency
that openbgpd is compiled somewhere since it uses a few of the objects.
I intend to get rid of this nastyness and only have a dependency on 
the header files. Probably not a problem.

One of the things to note here is that I strongly urge users of this to 
not have their box actively participate in routing, but instead to utilize
openbgpd and have this code send a community string. That way your upstream
router can be configured with route-maps to do whatever (e.g., null route,
next-hops). 

Here is an example of a next-hop configuration using cisco. 

CISCO:
	ASN = 1
	IP  = 10.211.55.5

OPENBGPD:
	ASN = 666
	IP  = 10.211.55.3

!
router bgp 1
 bgp router-id 10.211.55.5
 neighbor 10.211.55.3 remote-as 666
 neighbor 10.211.55.3 route-map nexthopcommunity in
!
ip community-list 1 permit 666:30
!
route-map nexthopcommunity permit 10
 match community 1
 set ip next-hop 10.211.55.1
!

This tells the router that any advertisement from 10.211.55.3 with
a community 666:30 will be locally next-hopped to 10.211.55.1
