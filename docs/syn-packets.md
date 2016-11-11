# Syn Packet Scans

We want to capture valid traffic so we can analyze the SYN packets various
applications send when initiating and establishing new connections. This is
important to us because we may want to emulate various types of traffic. The
last thing we want to do is bring attention to our traffic.
 
The first packet sent when initiating a TCP connection is a SYN packet. SYN
packets are typically sent by applications, e.g., browsers and SSH clients.


## Packet Captures

Our location (point-of-view) on the network might be important. For the sake of
completeness we should watch packet from the destination and from a network tap
on either the destination or source network. (FUTURE WORK)

The following packet captures were captured on the destination host.

### SSH client, server not running ###

17:45:55.855234 IP6 localhost.42690 > localhost.ssh: Flags [S], seq 1953961281, win 43690, options [mss 65476,sackOK,TS val 100558763 ecr 0,nop,wscale 7], length 0
17:45:55.855251 IP6 localhost.ssh > localhost.42690: Flags [R.], seq 0, ack 1953961282, win 0, length 0
17:45:55.855305 IP localhost.36062 > localhost.ssh: Flags [S], seq 4109018131, win 43690, options [mss 65495,sackOK,TS val 100558763 ecr 0,nop,wscale 7], length 0
17:45:55.855323 IP localhost.ssh > localhost.36062: Flags [R.], seq 0, ack 4109018132, win 0, length 0


### SSH client, server running ###

17:51:38.465717 IP6 localhost.42700 > localhost.ssh: Flags [S], seq 997009637, win 43690, options [mss 65476,sackOK,TS val 100901373 ecr 0,nop,wscale 7], length 0
17:51:38.465767 IP6 localhost.ssh > localhost.42700: Flags [S.], seq 3077065176, ack 997009638, win 43690, options [mss 65476,sackOK,TS val 100901373 ecr 100901373,nop,wscale 7], length 0
17:51:38.465797 IP6 localhost.42700 > localhost.ssh: Flags [.], ack 1, win 342, options [nop,nop,TS val 100901373 ecr 100901373], length 0
17:51:38.466727 IP6 localhost.42700 > localhost.ssh: Flags [P.], seq 1:22, ack 1, win 342, options [nop,nop,TS val 100901374 ecr 100901373], length 21
17:51:38.466759 IP6 localhost.ssh > localhost.42700: Flags [.], ack 22, win 342, options [nop,nop,TS val 100901374 ecr 100901374], length 0
17:51:38.488769 IP6 localhost.ssh > localhost.42700: Flags [P.], seq 1:22, ack 22, win 342, options [nop,nop,TS val 100901396 ecr 100901374], length 21
17:51:38.489158 IP6 localhost.42700 > localhost.ssh: Flags [.], ack 22, win 342, options [nop,nop,TS val 100901397 ecr 100901396], length 0
17:51:38.489786 IP6 localhost.42700 > localhost.ssh: Flags [P.], seq 22:1358, ack 22, win 342, options [nop,nop,TS val 100901397 ecr 100901396], length 1336
17:51:38.496877 IP6 localhost.ssh > localhost.42700: Flags [P.], seq 22:998, ack 1358, win 1365, options [nop,nop,TS val 100901404 ecr 100901397], length 976
17:51:38.500227 IP6 localhost.42700 > localhost.ssh: Flags [P.], seq 1358:1406, ack 998, win 357, options [nop,nop,TS val 100901408 ecr 100901404], length 48
17:51:38.507047 IP6 localhost.ssh > localhost.42700: Flags [P.], seq 998:1362, ack 1406, win 1365, options [nop,nop,TS val 100901414 ecr 100901408], length 364
17:51:38.548125 IP6 localhost.42700 > localhost.ssh: Flags [.], ack 1362, win 372, options [nop,nop,TS val 100901456 ecr 100901414], length 0
17:51:41.575443 IP6 localhost.42700 > localhost.ssh: Flags [P.], seq 1406:1422, ack 1362, win 372, options [nop,nop,TS val 100904483 ecr 100901414], length 16
17:51:41.616181 IP6 localhost.ssh > localhost.42700: Flags [.], ack 1422, win 1365, options [nop,nop,TS val 100904524 ecr 100904483], length 0
17:51:41.616281 IP6 localhost.42700 > localhost.ssh: Flags [P.], seq 1422:1466, ack 1362, win 372, options [nop,nop,TS val 100904524 ecr 100904524], length 44
17:51:41.616296 IP6 localhost.ssh > localhost.42700: Flags [.], ack 1466, win 1365, options [nop,nop,TS val 100904524 ecr 100904524], length 0
17:51:41.616434 IP6 localhost.ssh > localhost.42700: Flags [P.], seq 1362:1406, ack 1466, win 1365, options [nop,nop,TS val 100904524 ecr 100904524], length 44
17:51:41.616463 IP6 localhost.42700 > localhost.ssh: Flags [.], ack 1406, win 372, options [nop,nop,TS val 100904524 ecr 100904524], length 0
17:51:41.616597 IP6 localhost.42700 > localhost.ssh: Flags [P.], seq 1466:1534, ack 1406, win 372, options [nop,nop,TS val 100904524 ecr 100904524], length 68
17:51:41.617713 IP6 localhost.ssh > localhost.42700: Flags [P.], seq 1406:1490, ack 1534, win 1365, options [nop,nop,TS val 100904525 ecr 100904524], length 84
17:51:41.622480 IP6 localhost.42700 > localhost.ssh: Flags [P.], seq 1534:2162, ack 1490, win 372, options [nop,nop,TS val 100904530 ecr 100904525], length 628
17:51:41.629094 IP6 localhost.ssh > localhost.42700: Flags [P.], seq 1490:1574, ack 2162, win 1386, options [nop,nop,TS val 100904537 ecr 100904530], length 84
17:51:41.670053 IP6 localhost.42700 > localhost.ssh: Flags [.], ack 1574, win 372, options [nop,nop,TS val 100904578 ecr 100904537], length 0
17:51:48.832214 IP6 localhost.42700 > localhost.ssh: Flags [P.], seq 2162:2310, ack 1574, win 372, options [nop,nop,TS val 100911740 ecr 100904537], length 148
17:51:48.852910 IP6 localhost.ssh > localhost.42700: Flags [P.], seq 1574:1602, ack 2310, win 1406, options [nop,nop,TS val 100911760 ecr 100911740], length 28
17:51:48.852957 IP6 localhost.42700 > localhost.ssh: Flags [.], ack 1602, win 372, options [nop,nop,TS val 100911761 ecr 100911760], length 0
17:51:48.853106 IP6 localhost.42700 > localhost.ssh: Flags [P.], seq 2310:2422, ack 1602, win 372, options [nop,nop,TS val 100911761 ecr 100911760], length 112
17:51:48.894009 IP6 localhost.ssh > localhost.42700: Flags [.], ack 2422, win 1406, options [nop,nop,TS val 100911802 ecr 100911761], length 0
17:51:48.951736 IP6 localhost.ssh > localhost.42700: Flags [P.], seq 1602:2102, ack 2422, win 1406, options [nop,nop,TS val 100911859 ecr 100911761], length 500
17:51:48.992030 IP6 localhost.42700 > localhost.ssh: Flags [.], ack 2102, win 388, options [nop,nop,TS val 100911900 ecr 100911859], length 0
17:51:48.992143 IP6 localhost.ssh > localhost.42700: Flags [P.], seq 2102:2146, ack 2422, win 1406, options [nop,nop,TS val 100911900 ecr 100911900], length 44
17:51:48.992158 IP6 localhost.42700 > localhost.ssh: Flags [.], ack 2146, win 388, options [nop,nop,TS val 100911900 ecr 100911900], length 0
17:51:48.992667 IP6 localhost.42700 > localhost.ssh: Flags [P.], seq 2422:2950, ack 2146, win 388, options [nop,nop,TS val 100911900 ecr 100911900], length 528
17:51:48.992701 IP6 localhost.ssh > localhost.42700: Flags [.], ack 2950, win 1427, options [nop,nop,TS val 100911900 ecr 100911900], length 0
17:51:48.998475 IP6 localhost.ssh > localhost.42700: Flags [P.], seq 2146:2254, ack 2950, win 1427, options [nop,nop,TS val 100911906 ecr 100911900], length 108
17:51:48.998828 IP6 localhost.ssh > localhost.42700: Flags [P.], seq 2254:2330, ack 2950, win 1427, options [nop,nop,TS val 100911906 ecr 100911900], length 76
17:51:48.998875 IP6 localhost.42700 > localhost.ssh: Flags [.], ack 2330, win 388, options [nop,nop,TS val 100911906 ecr 100911906], length 0
17:51:49.084702 IP6 localhost.ssh > localhost.42700: Flags [P.], seq 2330:2390, ack 2950, win 1427, options [nop,nop,TS val 100911992 ecr 100911906], length 60
17:51:49.086995 IP6 localhost.ssh > localhost.42700: Flags [P.], seq 2390:2474, ack 2950, win 1427, options [nop,nop,TS val 100911995 ecr 100911906], length 84
17:51:49.087090 IP6 localhost.42700 > localhost.ssh: Flags [.], ack 2474, win 388, options [nop,nop,TS val 100911995 ecr 100911992], length 0




