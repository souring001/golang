package main

import (
    "fmt"
    "strings"
    "github.com/google/gopacket"
    "github.com/google/gopacket/pcap"
    "github.com/google/gopacket/layers"
    "log"
    "time"
)

type layerMeta struct{
    color uint32
}

var (
    ipAddr       string = "172.16.80.82"
    ipAddr6       string = "fe80::18a6:7432:1897:917b"
    device       string = "en0"
    snapshot_len int32  = 1024
    promiscuous  bool   = false
    err          error
    timeout      time.Duration = 50 * time.Millisecond
    handle       *pcap.Handle
    layerMap = map[string]layerMeta{
        "arp": layerMeta{ color: 0x000000 },
        "icmp": layerMeta{ color: 0x000000 },
        "tcp": layerMeta{ color: 0xFFFFFF },
        "udp": layerMeta{ color: 0x000000 },
        "igmp": layerMeta{ color: 0x000000 },
        "dns": layerMeta{ color: 0x000000 },
        "dhcp": layerMeta{ color: 0x000000 },
        "anomaly": layerMeta{ color: 0x000000 },
    }
)

func main() {
    // Open device
    handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
    if err != nil {log.Fatal(err) }
    defer handle.Close()

    // Set filter
    // var filter string = "tcp and port 80"
    // err = handle.SetBPFFilter(filter)
    // if err != nil {
    //     log.Fatal(err)
    // }
    // fmt.Println("Only capturing TCP port 80 packets.")

    // Use the handle as a packet source to process all packets
    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
    fmt.Println("start capturing...")

    for packet := range packetSource.Packets() {
        reverse := true
        if net := packet.NetworkLayer(); net != nil {
          src, dst := net.NetworkFlow().Endpoints()
          isSrc := strings.Contains(src.String(), ipAddr) || strings.Contains(src.String(), ipAddr6)
          isDst := strings.Contains(dst.String(), ipAddr)
          // if !((isSrc && !isDst) || (!isSrc && isDst)) {
          //     fmt.Println("src:", src, isSrc, "\tdst:", dst, isDst)
          // }
          fmt.Println("src:", src, isSrc, "\tdst:", dst, isDst)
          if isSrc {
              reverse = false
          }
        }
        if reverse {
            fmt.Println("<-")
        } else {
            fmt.Println("->")
        }

        packetName := categorizePacket(packet)
        fmt.Println(packetName)
        fmt.Println(layerMap[packetName].color)
    }
}

func categorizePacket(packet gopacket.Packet) string {
    packetName := "others";
    if lldp := packet.Layer(layers.LayerTypeLinkLayerDiscovery); lldp != nil {
        packetName = "lldp"
    }else if dns := packet.Layer(layers.LayerTypeDNS); dns != nil {
        packetName = "dns"
    }else if icmpv4 := packet.Layer(layers.LayerTypeICMPv4); icmpv4 != nil {
        packetName = "icmp"
    }else if icmpv6 := packet.Layer(layers.LayerTypeICMPv6); icmpv6 != nil {
        packetName = "icmp"
    }else if dhcpv4 := packet.Layer(layers.LayerTypeDHCPv4); dhcpv4 != nil {
        packetName = "dhcp"
    }else if arp := packet.Layer(layers.LayerTypeARP); arp != nil {
        packetName = "arp"
    }else if igmp := packet.Layer(layers.LayerTypeIGMP); igmp != nil {
        packetName = "igmp"
    }else if udp := packet.Layer(layers.LayerTypeUDP); udp != nil {
        packetName = "udp"
    }else if tcp := packet.Layer(layers.LayerTypeTCP); tcp != nil {
        packetName = "tcp"
    }
    return packetName
}
