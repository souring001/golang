package main
import (
	"fmt"
	"net"
	)

const (
    count = 39
	IPv4len = 4
)

func main() {
	ipaddr := "192.168.80.24"
	led := make([]uint32, count)
	showIPaddress(led, ipaddr)
}

func showIPaddress(led []uint32, ipaddr string) {
	ip := net.ParseIP(ipaddr)
	ipv4 := ip.To4()

	fmt.Println(ipv4[0])

    initLed(led)
	for i := 0; i < IPv4len; i++ {

		//number
		for j := 0; j < 8; j++ {
			t := i * 9 + j
	        led[t] = uint32((ipv4[i]>>(7-j))&1)
	    }

		// period
		led[(i+1) * 9 - 1] = uint32(2)
	}
    fmt.Println(led)
}

func initLed(led []uint32) {
    for i, _ := range led {
        led[i] = 0
    }
}
