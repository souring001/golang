package main

import (
	"errors"
	"fmt"
	"net"
)

func main() {

	ip4, ip6, mac, err := externalIP3()
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(ip4, ip6, mac)

}

func externalIP() (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
    var ipaddr net.IP
	for _, iface := range ifaces {
		fmt.Println(iface, iface.Name)
		if iface.Flags&net.FlagUp == 0 {
			continue // interface down
		}
		if iface.Flags&net.FlagLoopback != 0 {
			continue // loopback interface
		}
		addrs, err := iface.Addrs()
		if err != nil {
			return "", err
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() {
				continue
			}
			fmt.Println(ip)
			ip = ip.To4() //To16 if IPv6
			if ip == nil {
				continue // not an ipv4 address
			}
            ipaddr = ip
			// return ip.String(), nil
		}
    }
    if ipaddr == nil{
        return "", errors.New("are you connected to the network?")
    }else{
        return ipaddr.String(), nil
    }
}

func externalIP2() (string, string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", "", err
	}
    var ipv4Addr net.IP
    var ipv6Addr net.IP
	for _, iface := range ifaces {
        if iface.Name != "en0" {
            continue // select device "eth0" or something
        }
		addrs, err := iface.Addrs()
		if err != nil {
			return "", "", err
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() {
				continue
			}
			if ipv4 := ip.To4(); ipv4 != nil {
				ipv4Addr = ipv4
			}else if ipv6 := ip.To16(); ipv6 != nil {
				ipv6Addr = ipv6
			}
		}
    }
    if ipv4Addr == nil{
        return "", "", errors.New("are you connected to the network?")
    }else{
        return ipv4Addr.String(), ipv6Addr.String(), nil
    }
}

func externalIP3() (string, string, string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", "", "", err
	}
    var ipv4Addr net.IP
    var ipv6Addr net.IP
		var mac string
	for _, iface := range ifaces {
        if iface.Name != "en0" {
            continue // select device "eth0" or something
        }
		mac = iface.HardwareAddr.String()
		addrs, err := iface.Addrs()
		if err != nil {
			return "", "", "", err
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() {
				continue
			}
			if ipv4 := ip.To4(); ipv4 != nil {
				ipv4Addr = ipv4
			}else if ipv6 := ip.To16(); ipv6 != nil {
				ipv6Addr = ipv6
			}
		}
    }
    if ipv4Addr == nil{
        return "", "", "", errors.New("are you connected to the network?")
    }else{
        return ipv4Addr.String(), ipv6Addr.String(), mac, nil
    }
}
