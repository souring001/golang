package main

import (
    "fmt"
)

type layerMeta struct{
    color uint32
}

var (
    layerMap = make(map[string]layerMeta)
)

func main() {
    layerMap["tcp"] = layerMeta{
		color: 0xFFFFFF,
	}
    packetName := categorizePacket()
    fmt.Println(layerMap[packetName].color)
}

func categorizePacket() string {
    return "tcp"
}
