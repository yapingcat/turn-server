package goturn

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

var relayCenter map[string]*relayConn
var rcmtx sync.Mutex

func init() {
	relayCenter = make(map[string]*relayConn)
}

func addRelayConn(key string, relay *relayConn) {
	rcmtx.Lock()
	defer rcmtx.Unlock()
	relayCenter[key] = relay
}

func removeRelay(key string) {
	rcmtx.Lock()
	defer rcmtx.Unlock()
	if r, found := relayCenter[key]; found {
		r.stop()
	}
	delete(relayCenter, key)
}

func hasRelayConn(key string) bool {
	rcmtx.Lock()
	defer rcmtx.Unlock()
	_, found := relayCenter[key]
	return found
}

func fetchRelayConn(key string) (*relayConn, error) {
	rcmtx.Lock()
	defer rcmtx.Unlock()
	if r, found := relayCenter[key]; found {
		return r, nil
	} else {
		return nil, errors.New("Not Found " + key)
	}
}

type relayChannelMessage struct {
	channel uint16
	data    []byte
}

type relayIndicationMessage struct {
	peer net.Addr
	data []byte
}

type relayConn struct {
	conn      *net.UDPConn
	allocate  *TurnAllocation
	server    *STUNServer
	stopflag  bool
	writqueue chan interface{}
	quit      chan struct{}
	die       sync.Once
}

func newRelayConn(c *net.UDPConn) *relayConn {
	conn := &relayConn{
		writqueue: make(chan interface{}, 10),
		quit:      make(chan struct{}),
		stopflag:  true,
		conn:      c,
	}
	return conn
}

func (r *relayConn) start() {
	r.stopflag = false
	go r.readInloop()
	go r.sendInloop()
}

func (r *relayConn) stop() {
	r.die.Do(func() {
		r.stopflag = true
		r.conn.Close()
		close(r.quit)
	})
}

func (r *relayConn) readInloop() {
	recvBuf := make([]byte, 1500)
	for !r.stopflag {
		n, peer, err := r.conn.ReadFrom(recvBuf[4:])
		if err != nil {
			fmt.Println(err)
			break
		}
		permission, found := r.allocate.findTurnPermissionByAddr(peer)
		if !found || time.Now().After(permission.expired) {
			continue
		}

		if channel, found := r.allocate.findTurnChannelByAddr(peer); found {
			r.relayChannelData(recvBuf[0:n+4], channel)
		} else {
			fmt.Println("not found channel")
			r.replayIndicationData(recvBuf[4:n+4], peer)
		}
	}
}

func (r *relayConn) inputMessage(msg interface{}) {
	timeout := time.NewTimer(time.Second * 1)
	c := timeout.C
	select {
	case r.writqueue <- msg:
	case <-c:
		fmt.Println("Send Data Timeout")
		return
	}
}

func (r *relayConn) sendInloop() {
	for !r.stopflag {
		select {
		case msg := <-r.writqueue:
			switch value := msg.(type) {
			case *relayChannelMessage:
				r.onChannelData(value)
			case *relayIndicationMessage:
				fmt.Println("relay forward indication message")
				r.onIndicationData(value)
			}
		case <-r.quit:
			return
		}
	}
}

func (r *relayConn) onChannelData(msg *relayChannelMessage) {
	if ch, ok := r.allocate.findTurnChannel(msg.channel); ok {
		addr, _ := net.ResolveUDPAddr("udp4", ch.ip+":"+ch.port)
		r.conn.WriteTo(msg.data, addr)
	}
}

func (r *relayConn) onIndicationData(msg *relayIndicationMessage) {
	fmt.Printf("relay indication %s\n", msg.peer.String())
	r.conn.WriteTo(msg.data, msg.peer)
}

func (r *relayConn) relayChannelData(data []byte, channel *TurnChannel) {
	if time.Now().After(channel.expired) {
		fmt.Println("channel expired")
		return
	}

	binary.BigEndian.PutUint16(data[0:], channel.channel)
	binary.BigEndian.PutUint16(data[2:], uint16(len(data)-4))
	r.server.reponseChannelData(data, r.allocate.addr.remote)
}

func (r *relayConn) replayIndicationData(data []byte, peer net.Addr) {
	var msg STUNMessage
	msg.msgclass = INDICATION
	msg.method = STUN_METHOD_DATA
	msg.transactionId = genTransactionId()
	msg.addXORAddressByAddr(XOR_PEER_ADDRESS, peer, IPV4)
	msg.addData(data)
	msg.addCredentials(r.server.term, r.allocate.auth)
	msg.addFingerprint()
	r.server.stunReponse(msg, r.allocate.addr.remote)
}
