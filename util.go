package goturn

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"strings"
	"time"
	"unsafe"
)

const (
	IPV4 = 0
	IPV6 = 1
)

var nativeEndian binary.ByteOrder

func init() {
	rand.Seed(time.Now().Unix())
	buf := [2]byte{}
	*(*uint16)(unsafe.Pointer(&buf[0])) = uint16(0xABCD)

	switch buf {
	case [2]byte{0xCD, 0xAB}:
		fmt.Print("little endian")
		nativeEndian = binary.LittleEndian
	case [2]byte{0xAB, 0xCD}:
		nativeEndian = binary.BigEndian
	default:
		panic("Could not determine native endianness.")
	}
}

func checkIPAddressType(ip string) int {
	if strings.Contains(ip, ":") {
		return IPV6
	} else {
		return IPV4
	}
}

func align4Bytes(length uint16) uint16 {
	return (length + 3) / 4 * 4
}

func genReservedToken() (token []byte) {
	token = make([]byte, 8)
	for i := 0; i < 8; i++ {
		token[i] = byte(rand.Uint32())
	}
	return
}

func genTransactionId() (id [12]byte) {
	for i := 0; i < 8; i++ {
		id[i] = byte(rand.Uint32())
	}
	return
}
