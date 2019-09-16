package main

import (
    "fmt"
    "github.com/google/gopacket"
    "github.com/google/gopacket/pcap"
    "github.com/google/gopacket/layers"
    "log"
    "time"
)

var (
    device       string = "en0"
    snapshot_len int32  = 1024
    promiscuous  bool   = false
    err          error
    timeout      time.Duration = 50 * time.Millisecond
    handle       *pcap.Handle
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

        if tcp := packet.Layer(layers.LayerTypeTCP); tcp != nil {
            // fmt.Println("TCP")
        }else if udp := packet.Layer(layers.LayerTypeUDP); udp != nil {
            // fmt.Println("UDP")
            // fmt.Println(packet)
        }else if arp := packet.Layer(layers.LayerTypeARP); arp != nil {
            // fmt.Println("ARP")
            // fmt.Println(packet)
        }else if lldp := packet.Layer(layers.LayerTypeLinkLayerDiscovery); lldp != nil {
            // fmt.Println("LLDP")
            // fmt.Println(packet)ICMPv4
        }else if icmpv4 := packet.Layer(layers.LayerTypeICMPv4); icmpv4 != nil {
            fmt.Println("ICMPv4")
            fmt.Println(packet)
        }else{
            // fmt.Println("OTHERS")
            // fmt.Println(packet)
        }



        // Process packet here
        // fmt.Println(packet)
    }
}
