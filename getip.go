package main

import (
	"errors"
	"fmt"
	"net"
)

func main() {

	ip, err := externalIP()
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(ip)

}

func externalIP() (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
    var ipaddr net.IP
	for _, iface := range ifaces {
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
