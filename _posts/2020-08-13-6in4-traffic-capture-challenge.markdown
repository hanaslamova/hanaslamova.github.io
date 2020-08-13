---
layout: post
title:  "6in4 Traffic Capture Challenge"
date:   2020-08-13 16:00:00 +0200
---
This post is about 6in4 Traffic Capture article by [Johannes Weber](https://twitter.com/webernetz). You can find the whole post [here](https://weberblog.net/6in4-traffic-capture/), including PCAP file containing data for the challenge.

Althougth the right answers can be viewed below the article in a comment issued by [Sake Blok](https://twitter.com/SYNbit), I thought that would be nice to write up my approach to solving this challenge.  Since the writeup didn't look difficult, I found it as a great topic for a first blog post.

So, let's begin! Below you can find all stated questions, answers and my explanation to them.

## 1) What’s the serial number of the Juniper SSG 140?
From setup section in the original post we know that Juniper SSG 140 has IPv4 address 193.24.227.10. To see communication received/sent by this device, using filter `ip.host == 193.24.227.10` should be enough. A part of the result can be seen in the image below.

![](/images/6in4-traffic-capture-challenge/syslog.png "Output for ip.host == 193.24.227.10 filter.")

First few packets belong to *SYSLOG* protocol, which permits to log information from variation of devices in a single repository. Syslog packet contains information such as *facility code* - type of application creating the log information, *severity level* - how important is that log information? (0- most important, 7- least important) or *message* - logging information. Message contains info regarding event on which device is creating the log. It can have format of pairs - tag, value. The message  part can be seen in Info column. 

In our example, info column contains interesting data, specifically the value for **device_id** tag:

> ssg: NetScreen **device_id=0185082008001541**  [Root]system-notification-00257(traffic): start_time="2019-05-09 14:50:16" duration=59 policy_id=1 service=dns proto=17 src zone=Trust dst zone=Untrust action=Permit sent=136 rcvd=0 src=193.24.227.196 dst=9.9.9.9 src_port=55687 dst_port=53 src-xlated ip=193.24.227.196 port=55687 dst-xlated ip=9.9.9.9 port=53 session_id=48059 reason=Close - AGE OUT

Since message part's format depends on particular usage, in our case, this could be the answer we are looking for.

## 2) What reference time source is used on the stratum 1 NTP server?
*NTP* protocol is used for clock synchronization between devices. Sources, from which device synchronizes its clock, are divided into so called *stratums* - levels, which determine the distance from the ‘reference time source’. Device at stratum 1 synchronizes its clocks with device on stratum 0, devices on stratum 2 with devices on stratum 1 and so on… 

To see only NTP protocol traffic we can use `ntp` filter. Only two messages are showed. First is client's request to server for time, second is server's answer. Here we can find field we are looking for - **Reference ID**.

![](/images/6in4-traffic-capture-challenge/ntp.png "NTP packet issued by server.")

## 3) Which operating system sent the ping?
The question does not specify which type of ping (*ICMP* or *ICMPv6*?)  we should investigate, following text tries to explain it for both versions.

When we are trying to determine ones computer operating system, methods to accomplish this task can be divided into two groups - *active* and *passive fingerprinting*. The differences is that active fingerprinting somehow interacts with target machine, the latter does not.

Since we do not have access to machines to interact with them and hence we are not able to perform active OS fingerprinting, I will not mention these methods here.

The only source of information we have is provided in the PCAP file - in which ways can we determine machine's operating system?
Approaches to be known to me:
- TTL/hop limit of ICMP/ICMPv6 packet
- Windows size in TCP
- User agent in HTTP (or other banners)

Let's first note down, which machines sent ping. To see them let's use filter `icmpv6.type == 128 or icmp.type==8` to show only ICMP or ICMPv6 requests.

![](/images/6in4-traffic-capture-challenge/icmp.png "ICMP requests.")

IP addresses we are interested in:
- `34.255.152.202`
- `2001:470:1f0b:16b0:20c:29ff:fe7c:a4cb`

### ICMP
In case of ICMPv6 (even ICMP) the operating system can be identified by *hop limit* (by *TTL* in case of ICMP). TTL/hop limit serves as a counter saying "how many routers can I pass". When an IP packet arrives at a router, the router decrement this value, looks on its new value and if it is zero the packet is thrown away. This way, it can't happen that packet would be traveling over the network forever.

When packet is leaving a computer, the computer sets TTL/hop limit a specific value based on its operating system. 

The specific values for each operating system are summarized below. There we can see that Linux machines issue IP packets with TTL 64, Windows with value 128 and iOS with value 255. 

| Operating System                | Time To Live |
| ------------------------------- | ------------ |
| Linux (Kernel 2.4 and 2.6)      | 64           |
| Google Linux                    | 64           |
|FreeBSD                          |	64           |
|Windows XP                       |	128          |
|Windows Vista and 7 (Server 2008)|	128          |
|iOS 12.4 (Cisco Routers)	      | 255          |

Source of this table is [here](https://www.howtogeek.com/104337/hacker-geek-os-fingerprinting-with-ttl-and-tcp-window-sizes/). More comprehensive list can be found [here](https://subinsb.com/default-device-ttl-values/).

#### IPv4
Lets go back to our case and apply this knowledge. In our interest is only one IPv4 address - `34.255.152.202`. If we look into image above, we can see this IP address issued ICMP request with TTL 234. It looks like it started on value 255 and passed 21 routers by the way to our capture. According to table above we can say it was not issued by Windows machine. 

But why Sake Blok says that they are probably Linux machines even though the value is not 64 or below as table says? I think that to determine precisely what type of OS is running on the machine through only ICMP can be tricky. If we take a look into table in [this article](https://subinsb.com/default-device-ttl-values/), we can see that for MacOS(Unix)  TTL values are around 60 and for Linux  the values are sometimes 255 or 64. In both cases, they are never 128. Windows machines has mostly TTL value 128. Hence, saying it is not Windows machine, but probably Linux/Unix, is reasonable.

#### IPv6
Here ICMP request is issued  by `2001:470:1f0b:16b0:20c:29ff:fe7c:a4cb` has TTL 62. Since it has not value 128, we can say that it is not probably Windows machine.

### Can we apply other mentioned approaches to determine machine's OS?
`34.255.152.202` - To see all traffic issued by this IP address lets apply filter `ip.src == 34.255.152.202`. Result is showing only already investigated ICMP traffic.

`2001:470:1f0b:16b0:20c:29ff:fe7c:a4cb` - For this IP address we apply following filter `ipv6.src == 2001:470:1f0b:16b0:20c:29ff:fe7c:a4cb`. Except the ICMPv6 packets, we can see DNS query. Unfortunatelly I am afraid this type of packets indicates nothing about OS.

## 4) Which server (vhost) was accessed in TCP stream 4?
Great way to begin is to display only tcmp stream 4 traffic - `tcp.stream == 4`. We can see *TLS* traffic. In Wikipedia for this keyword we can found that TLS protocol provides privacy and data integrity over TCP layer and incorporates unencrypted handshake, where both sides agree on which encryption and other algorithms important for security they will use. Nice!

Possible next step in analysis is to right-click on first packet and navigate to `Follow -> TCP Stream`. A part of the result is displayed below.

![](/images/6in4-traffic-capture-challenge/tcpStream4.png "A part of TCP stream 4.")

There are some readable strings, such as **random.weberlab.de**. Is this the answer we are looking for? If we double click on the interesting string, Wireshark throws us to packet number 94 - *Client Hello message*.
Hmm.. Let's gather more info about this type of packet.

I encountered interesting [blog post](https://idea.popcount.org/2012-06-16-dissecting-ssl-handshake/). There in a paragraph about extensions is mentioned field *server_name*, saying that this field is used to specify a remote host name. 
If we look in our capture this is the place where the interesting string is contained. :)

![](/images/6in4-traffic-capture-challenge/serverName.png "server_name field in Client Hello message.")

## 5) How many authoritative DNS answers were sent from my lab?
*DNS* is client-server protocol. Authoritative server provides original, authoritative answers. Not cached ones. Each domain (e.g example.com) can have a set of authoritative servers.
How is noted in the [comment](https://weberblog.net/6in4-traffic-capture/#comment-48406) from Sake Block, filter `dns.flags.response == 1 && dns.count.auth_rr> 0` is enough to answer this question. The filter says - show me only DNS response messages which have count of authoritative records greater than zero. 

## 6) What are the authoritative name servers?
To discover  which authoritative servers given domain has, *NS record type* is used.  For example putting `dig google.com ns` into a command line will give me following result:

        ;; ANSWER SECTION:
        google.com. 134032 IN NS ns4.google.com.
        google.com. 134032 IN NS ns3.google.com.
        google.com. 134032 IN NS ns1.google.com.
        google.com. 134032 IN NS ns2.google.com.

We can use filter `dns.ns` to see packets containig NS record type.

![](/images/6in4-traffic-capture-challenge/ns.png "ns1.weberdns.de and ns2.weberdns.de are authoritative name server.")

## 7) Which DNSSEC algorithm is weberlab.de using?
*DNSSEC* is not protocol by itself but rather a set of DNS records to improve DNS security. According to [RFC 4034](https://tools.ietf.org/html/rfc4034), a part of DNSSEC are following records (number in round brackets represents record type number):
- *DNSKEY* (48)
- *RRSIG* (46)
- *NSEC* (47)
- *DS* (43)

To display only any DNS message that contains one of these records use filter - `dns.resp.type == 48 or dns.resp.type == 46 or dns.resp.type == 47 or dns.resp.type == 43`.

Now if we look into detail to one of these records we can see field Algorithm.

![](/images/6in4-traffic-capture-challenge/dnssec.png "DNSSEC algorithm.")

## 8) Which DNS client sent a cookie? What’s its value?
Information that DNS uses cookies was new for me, so I googled a bit about it.
In [RFC 7873](https://tools.ietf.org/html/rfc7873) we can read following:
- DNS cookie is a lightweight DNS transaction security mechanism specified as an OPT option.  The DNS Cookie mechanism provides limited protection to DNS servers and clients against a variety of increasingly common abuses by off-path attackers. 
- It is specified in OPT option
- Attacks against which DNS cookie provides limited protection
    - DNS amplification attack,
    - DNS server denial attack
    - Cache poisoning
    - Answer forgery attack

These attacks, DNS cookie's influence on them and mechanism how it works is nicely explained in the referenced RFC 7873. I will not copy pasta it here, so please if you are interested definitely read the RFC. For now, what cookie is and where we can find it is enough to know to answer the challenge question.

First thing we want to do is to display only DNS requests. But wait, maybe Wireshark has implemented filter to show only messages, which contains DNS cookie - `dns.opt.cookie.client`. After applying this filter, only two messages are displayed.

First is client's query containing client cookie, second is server's response containing cookie which is client's and server's cookie merged into a single one.  We can choose which message we select and view the cookie. I selected server's response. Its cookie (and extracted client's cookie by Wireshark) can be seen below.

![](/images/6in4-traffic-capture-challenge/cookie.png "Server's response with DNS cookie.")

## 9) What’s the first HTML line from the answer in TCP stream 2?
Once again, let's use filter to display only specific TCP stream - `tcp.stream == 2`
Now we find first HTTP packet, left-click on it and navigate to `Follow -> HTTP Stream`.
Part of the result is shown below.

![](/images/6in4-traffic-capture-challenge/tcpStream2.png "A part of HTML in TCP stream 2.")

Red text are data sent by client, blue text are data sent by server. Since we want to know first HTML line from answer we need to look at the blue part. <table border="1" cellpadding="5" cellspacing="0"> could be the right answer.

## 	10) How many different server TLS certificates are in the trace?
To see all TLS messages which contain certificates we can use this filter - `tls.handshake.certificate`.

As a result, we will see only three messages. If we click on each, and take a look on Certificate sections (`Transport Layer Security -> TLSv1.2 Record… -> Handshake Protocol: Certificate -> Certificates`), we will see that all these three messages contains 2 same certificates.

## 11) What are the subject alternative names of the 1st certificate in TCP stream 5?
Good start is to display only TCP stream 5 and messages with TLS certificate - `tcp.stream eq 5 and tls.handshake.certificate`. This results into a single message. If we click on it and follow same path to Certificates as described in question above, we again will see two certificates.

If we further investigate first certificate we encounter **Extension (id-ce-subjectAltName)**.

![](/images/6in4-traffic-capture-challenge/cert.png "Extension (id-ce-subjectAltName).")

As a last step to answer this questions, let's open all the seven items in GeneralNames section:

![](/images/6in4-traffic-capture-challenge/generalNames.png "Subject alternative names.")