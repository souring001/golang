package main
import "fmt"

const (
    count = 10
    length = 3
)

func main() {
    led := make([]uint32, count)
    fmt.Println(led)

    castPacket(led, length, true)
}

func castPacket(led []uint32, k int, reverse bool) {
    for i := -(k-1); i < len(led)+1; i++ {
        initLed(led)

        for j := 0; j < k; j++ {
            if t := i + j; 0 <= t && t < len(led) {
                led[t] = uint32(8 * (j+1) / k)
            }
        }

        if reverse {
            reverseLed(led)
        }

        fmt.Println(led)
    }
}

func reverseLed(led []uint32) {
    for i, j := 0, len(led)-1; i < j; i, j = i+1, j-1 {
        led[i], led[j] = led[j], led[i]
    }
}

func initLed(led []uint32) {
    for i, _ := range led {
        led[i] = 0
    }
}
