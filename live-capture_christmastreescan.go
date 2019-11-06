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
    ipAddr       string = "172.16.80.82"
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

    // Use the handle as a packet source to process all packets
    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
    fmt.Println("start capturing...")

    for packet := range packetSource.Packets() {
        if isAnomaly(packet) {
            fmt.Println("aaa")
        }
        if udp := packet.Layer(layers.LayerTypeUDP); udp != nil {
            // fmt.Println("UDP")
            // if net := packet.NetworkLayer(); net != nil {
            //   src, dst := net.NetworkFlow().Endpoints()
            //   fmt.Println("src:", src, "\tdst:", dst)
            // }
            // fmt.Println(packet)
        }else if tcp := packet.Layer(layers.LayerTypeTCP); tcp != nil {
            // fmt.Println("TCP")
            // if net := packet.NetworkLayer(); net != nil {
            //   src, dst := net.NetworkFlow().Endpoints()
            //   fmt.Println("src:", src, "\tdst:", dst)
            // }
            // fmt.Println(packet)
        }else{
            // fmt.Println("OTHERS")
            // if net := packet.NetworkLayer(); net != nil {
            //   src, dst := net.NetworkFlow().Endpoints()
            //   fmt.Println("src:", src, "\tdst:", dst)
            // }
            // fmt.Println(packet)
        }
    }
}

func isAnomaly(packet gopacket.Packet) bool {
    anml := false
    if tcp := packet.Layer(layers.LayerTypeTCP); tcp != nil {
        tcpl, _ := tcp.(*layers.TCP)
        // Bool flags: FIN, SYN, RST, PSH, ACK, URG, ECE, CWR, NS
        if tcpl.FIN && tcpl.URG && tcpl.PSH {
            anml = true
        }
    }
    return anml
}
