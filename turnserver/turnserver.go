package main

import (
	"flag"
	"fmt"
	"math/rand"
	"net"
	"strconv"

	goturn "github.com/yapingcat/turn-server"
	"gopkg.in/ini.v1"
)

var cfgFile string

func init() {
	flag.StringVar(&cfgFile, "c", "turn.ini", "ini config")
}

func main() {
	flag.Parse()

	cfg, _ := ini.Load(cfgFile)
	username := cfg.Section("").Key("username").String()
	password := cfg.Section("").Key("password").String()
	port := cfg.Section("").Key("turn.port").MustUint64()
	externalIp := cfg.Section("").Key("turn.externalip").String()
	server := goturn.CreateSTUNServer(goturn.RFC_5389, goturn.STUN_LONG_TERM, goturn.STUN_LONG_TERM)
	server.SetExternalIP(externalIp)
	server.OnBind = func(req goturn.STUNRequest) error {
		fmt.Println(req.GetRemoteAddr().String())
		return nil
	}

	server.OnAuth = func(cred goturn.AUTH_TERM, username []byte, realm []byte, nonce []byte) (pwd []byte, err error) {
		pwd = []byte(password)
		err = nil
		return
	}

	server.GetNonce = func() (realm []byte, nonce []byte, err error) {
		realm = []byte("goturn")
		nonce = []byte("hello world")
		err = nil
		return
	}

	server.OnSharedSecret = func(req goturn.STUNRequest) (user []byte, pwd []byte, err error) {
		fmt.Println(req.GetRemoteAddr().String())
		user = []byte(username)
		pwd = []byte(password)
		err = nil
		return
	}

	server.OnBindIndication = func(req goturn.STUNRequest) error {

		fmt.Println("onBind Indication " + req.GetRemoteAddr().String())
		return nil
	}

	//In all cases, the server SHOULD only allocate ports from the range
	//49152 - 65535
	server.OnAllocated = func(evenport int) (relays []*net.UDPConn, err error) {
		for {
			portrange := 65535 - 49152
			port := rand.Uint32()%uint32(portrange) + 65535
			addr, _ := net.ResolveUDPAddr("udp4", "0.0.0.0:"+strconv.Itoa(int(port)))
			if conn, err := net.ListenUDP("udp4", addr); err != nil {
				continue
			} else {
				relays = append(relays, conn)
				break
			}
		}
		return
	}

	server.OnRefresh = func(local net.Addr, remote net.Addr, protocol int, lifetime int) {
		fmt.Printf("recv Refresh from client(%s) lifetime = %d\n", remote.String(), lifetime)
	}

	server.OnChannel = func(client net.Addr, peerIp string, port uint16, channelnumber int) {
		fmt.Printf("recv Refresh from client(%s) peer:%s port:%d,channelnumber:%d\n", client.String(), peerIp, port, channelnumber)
	}

	server.Start(uint16(port))
	select {}
}
