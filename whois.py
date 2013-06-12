#!/usr/bin/python
#
#
# whois query - discover the net!
# - ip lookup
#
# ripped some code from pywhois http://code.google.com/p/pywhois/
#
# brabo
#

import sys
import socket
from IPy import IP

whois_servers = [ "whois.ripe.net", "whois.apnic.net", "whois.arin.net", "whois.afrinic.net", "whois.lacnic.net" ]
newstart=""
end=""
check=0

print "Let's check the subnet allocations!"

def query ( start, source ):
    while True:

        check=0
        ip = IP(start)
        type=ip.iptype()
        if ( type == 'PRIVATE' ):
            (a, b, c, d) = start.split('.')
            c=int(c)+1
            start = str(a)+"."+str(b)+"."+str(c)+"."+str(d)
            source=1
            continue

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if ( int(source) == 1 ):
            whois_server=whois_servers[0]
        elif ( int(source) == 2 ):
            whois_server=whois_servers[1]
        elif ( int(source) == 3 ):
            whois_server=whois_servers[2]
        elif ( int(source) == 4 ):
            whois_server=whois_servers[3]
        elif ( int(source) == 5 ):
            whois_server=whois_servers[4]

        
        s.connect((whois_server, 43))
        queryBytes = None
        if ( int(source) == 3 ):
            queryBytes = (start + "\r\n").encode()
        else:
            queryBytes = ('-r '+start + "\r\n").encode()
        source=1
        s.send(queryBytes)
        response = b''
        while True:
            d = s.recv(4096)
            response += d
            if not d:
                break
        s.close()
        response=response.splitlines(True)

        for line in response:
            check=0
            if "netname" in line.lower():
                name=line.split()[1]
                if "IANA-NETBLOCK" in name:
                    source=3
                    break
                if "IANA-BLK" in name:
                    source=2
                    break
                elif "APNIC-NETBLOCK" in name:
                    source=2
                    break
                elif "AFRINIC-NETBLOCK" in name:
                    source=4
                    break
                elif "LACNIC-NETBLOCK" in name:
                    source=5
                    break
                print "-------------------------------\n\n-------------------------------"
                print start+" - "+end+"\n"+name
                start=newstart

            if "descr:" in line:
                    desc=line.split()[1:-1]
                    print ' '.join(desc)

            if "inetnum" in line and not "0.0.0.0" in line and check==0:
                check=1
	        end=line.split()[3] 
                end=end.split('\n')[0]
                (a, b, c, d) = end.split('.')

                if ( int(c) == 255 ):
                    if ( int(b) == 255 ):
                         a=int(a)+1
                         b=0
                    else:
                        b=int(b)+1
                    c=0
                else:
                    c=int(c)+1
                    d=0
                d=1
                newstart=str(a)+"."+str(b)+"."+str(c)+"."+str(d)

#        print "-----------------------------------"
#        print

a=3
start=str(a)+".0.0.1"
query(start, 1)
print "--------------------------FINISHED__________________-----------<#3"
