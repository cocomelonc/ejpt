package main

import (
	"fmt"
	"net"
)

func main() {
	for i := 1; i <= 1024; i++ {
		address := fmt.Sprintf("10.10.15.4:%d", i)
		conn, err := net.Dial("tcp", address)
		if err != nil {
			// either the port is filtered or closed
			continue
		}
		conn.Close()
		fmt.Printf("port %d: open\n", i)
	}
}
