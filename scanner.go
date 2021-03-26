package main

import (
	"fmt"
	"net"
	"sort"
)

func worker(ports, results chan int) {
	for p := range ports {
		address := fmt.Sprintf("10.10.15.4:%d", p)
		conn, err := net.Dial("tcp", address)
		if err != nil {
			results <- 0
			continue
		}
		conn.Close()
		results <- p
	}
}

func main() {

	// channel for ports
	ports := make(chan int, 100)

	// channel for results
	results := make(chan int)

	// for store results
	var openports []int

	// pool of workers
	for i := 0; i < cap(ports); i++ {
		go worker(ports, results)
	}

	// send ports to be scanned
	go func() {
		for i := 1; i <= 65535; i++ {
			ports <- i
		}
	}()

	for i := 0; i < 65535; i++ {
		port := <-results
		if port != 0 {
			openports = append(openports, port)
		}
	}

	// close the channels
	close(ports)
	close(results)

	// sort open port numbers
	sort.Ints(openports)
	for _, port := range openports {
		fmt.Printf("port %d: open\n", port)
	}
}
