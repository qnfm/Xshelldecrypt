package Xshelldecrypt

import (
	"crypto/rc4"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"os/user"
	"strings"

	"golang.org/x/example/hello/reverse"
)

func Recovery(pwd string) {
	curr, err := user.Current()
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	// Trim the domain
	split := strings.SplitAfter(curr.Username, "\\")
	name := split[len(split)-1]

	ikm := reverse.String(curr.Uid) + name
	decoded, err := base64.StdEncoding.DecodeString(pwd)
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	key := sha256.Sum256([]byte(ikm))
	arc, err := rc4.NewCipher(key[:])
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	pt := make([]byte, len(decoded)-32)
	arc.XORKeyStream(pt, decoded[:len(decoded)-32])
	calculatedHash := sha256.Sum256(pt[:])

	// Test the result
	iv := decoded[len(decoded)-32:]
	if subtle.ConstantTimeCompare(calculatedHash[:], iv) == 1 {
		fmt.Println(string(pt))
	} else {
		fmt.Println("Decryption failed")
	}
}
