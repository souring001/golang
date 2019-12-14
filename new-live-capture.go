package main

import (
    "fmt"
    "github.com/google/gopacket"
    "github.com/google/gopacket/pcap"
    "github.com/google/gopacket/layers"
    "log"
    "time"
    "os"
)

var (
    device       string = "en0"
    snapshot_len int32  = 1024
    promiscuous  bool   = false
    timeout      time.Duration = 50 * time.Millisecond
)

func main() {
    var eth layers.Ethernet
    var ip4 layers.IPv4
    var ip6 layers.IPv6
    var icmp4 layers.ICMPv4
    var icmp6 layers.ICMPv6
    var tcp layers.TCP
    var udp layers.UDP
    var arp layers.ARP
    var dhcp4 layers.DHCPv4
    var dhcp6 layers.DHCPv6
    var dns layers.DNS
    var tls layers.TLS
    var payload gopacket.Payload

    handle, err := pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
    if err != nil {log.Fatal(err) }
    defer handle.Close()

    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

    parser := gopacket.NewDecodingLayerParser(
        layers.LayerTypeEthernet,
        &eth,
        &ip4,
        &ip6,
        &icmp4,
        &icmp6,
        &tcp,
        &udp,
        &arp,
        &dhcp4,
        &dhcp6,
        &dns,
        &tls,
        &payload,
    )
    decoded := []gopacket.LayerType{}

    for packetData := range packetSource.Packets() {
        fmt.Println("-----------")
        // fmt.Println(packetData.Data())
        if err := parser.DecodeLayers(packetData.Data(), &decoded); err != nil {
            fmt.Fprintf(os.Stderr, "Could not decode layers: %v\n", err)
            continue
        }
        fmt.Println(decoded)
        for a, layerType := range decoded {
            fmt.Println(a, layerType)
            switch layerType {
                case layers.LayerTypeIPv6:
                    fmt.Println("    IP6 ", ip6.SrcIP, ip6.DstIP)
                case layers.LayerTypeIPv4:
                    fmt.Println("    IP4 ", ip4.SrcIP, ip4.DstIP)
            }
        }
    }
}
