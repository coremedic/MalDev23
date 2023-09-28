package main

import "fmt"

func caesar(b byte, shift int) byte {
	return byte((int(b) + shift) % 256)
}

func main() {
	// shellcode from metasploit
	shellcode := []byte{}

	// rotation value
	shift := 3

	// init a slice of bytes for the encrypted shellcode
	encryptedShellcode := make([]byte, len(shellcode))

	// encrypt each byte in the shellcode
	for i, b := range shellcode {
		encryptedShellcode[i] = caesar(b, shift)
	}

	// print encrypted shellcode in \xNN format
	fmt.Printf("\"")
	for i, b := range encryptedShellcode {
		fmt.Printf("\\x%02x", b)
		if (i%20 == 0) && i != 0 {
			fmt.Printf("\"\n\"")
		}
	}
	fmt.Printf("\"")
	fmt.Println()
}
