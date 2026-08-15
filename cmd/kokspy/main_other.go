//go:build !windows

package main

import "fmt"

func main() {
	fmt.Println("KokSpy GUI is a Windows desktop application. Build with GOOS=windows or use cmd/kokspy-cli for the portable console frontend.")
}
