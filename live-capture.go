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
    show bool
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
        "ARP":      layerMeta{ color: 0x000001, show: true },
        "ICMP":     layerMeta{ color: 0x000002, show: true },
        "TCP":      layerMeta{ color: 0x000003, show: true },
        "UDP":      layerMeta{ color: 0x000004, show: true },
        "IGMP":     layerMeta{ color: 0x000005, show: true },
        "DNS":      layerMeta{ color: 0x000006, show: true },
        "DHCP":     layerMeta{ color: 0x000007, show: true },
        "Anomaly":  layerMeta{ color: 0x000008, show: true },
        "Others":   layerMeta{ color: 0x000000, show: true },
    }
)

func main() {
    // Open device
    handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
    if err != nil {log.Fatal(err) }
    defer handle.Close()

    asd := layerMap["ARP"]
    asd.show = false
    layerMap["ARP"] = asd

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
        meta := layerMap[packetName]
        fmt.Println(meta.color)
        if meta.show {
            fmt.Println(packetName)
        }

        // cast(led, ... , meta.color)
    }
}

func categorizePacket(packet gopacket.Packet) string {
    packetName := "Others";
    if lldp := packet.Layer(layers.LayerTypeLinkLayerDiscovery); lldp != nil {
        packetName = "LLDP"
    }else if dns := packet.Layer(layers.LayerTypeDNS); dns != nil {
        packetName = "DNS"
    }else if icmpv4 := packet.Layer(layers.LayerTypeICMPv4); icmpv4 != nil {
        packetName = "ICMP"
    }else if icmpv6 := packet.Layer(layers.LayerTypeICMPv6); icmpv6 != nil {
        packetName = "ICMP"
    }else if dhcpv4 := packet.Layer(layers.LayerTypeDHCPv4); dhcpv4 != nil {
        packetName = "DHCP"
    }else if arp := packet.Layer(layers.LayerTypeARP); arp != nil {
        packetName = "ARP"
    }else if igmp := packet.Layer(layers.LayerTypeIGMP); igmp != nil {
        packetName = "IGMP"
    }else if udp := packet.Layer(layers.LayerTypeUDP); udp != nil {
        packetName = "UDP"
    }else if tcp := packet.Layer(layers.LayerTypeTCP); tcp != nil {
        packetName = "TCP"
    }
    return packetName
}
