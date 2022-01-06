package goturn

import (
	"container/list"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"
)

type STUNServer struct {
	port             uint16
	conn             *net.UDPConn
	version          STUN_VERSION
	stun_term        AUTH_TERM
	term             AUTH_TERM
	publicIp         string
	OnBind           func(req STUNRequest) error
	OnAuth           func(cred AUTH_TERM, username []byte, realm []byte, nonce []byte) (pwd []byte, err error)
	GetNonce         func() (realm []byte, nonce []byte, err error)
	OnSharedSecret   func(req STUNRequest) (user []byte, pwd []byte, err error)
	OnBindIndication func(req STUNRequest) error
	OnAllocated      func(evenport int) (relays []*net.UDPConn, err error)
	OnRefresh        func(local net.Addr, remote net.Addr, protocol int, lifetime int)
	OnChannel        func(client net.Addr, peerIp string, port uint16, channelnumber int)
}

func CreateSTUNServer(version STUN_VERSION, term AUTH_TERM, stunTerm AUTH_TERM) *STUNServer {
	server := &STUNServer{
		version:   version,
		term:      term,
		stun_term: stunTerm,
	}
	return server
}

func (s *STUNServer) Start(port uint16) error {
	s.port = port
	addr, err := net.ResolveUDPAddr("udp4", "0.0.0.0:"+strconv.Itoa(int(s.port)))
	if err != nil {
		return err
	}
	if s.conn, err = net.ListenUDP("udp4", addr); err != nil {
		return err
	}
	go s.cycle()
	return nil
}

func (s *STUNServer) restart() error {
	addr, err := net.ResolveUDPAddr("udp4", "0.0.0.0:"+strconv.Itoa(int(s.port)))
	if err != nil {
		return err
	}
	if s.conn, err = net.ListenUDP("udp4", addr); err != nil {
		return err
	}
	go s.cycle()
	return nil
}

func (s *STUNServer) SetExternalIP(ip string) {
	s.publicIp = ip
}

func (s *STUNServer) cycle() {
	msg := make([]byte, 1500)
	for {
		n, remoteaddr, err := s.conn.ReadFrom(msg)
		if err != nil {
			s.conn.Close()
			s.restart()
			return
		}

		//received channel data
		if n > 0 && (msg[0]&0xC0 == 0x40) {
			a, found := manager.findAllocatiionByTurnAddress(s.conn.LocalAddr(), remoteaddr, 0)
			if found != nil {
				continue
			}
			for _, r := range a.addr.relay {
				if relay, ok := fetchRelayConn(r.String()); ok == nil {
					var chmsg relayChannelMessage
					chmsg.channel = binary.BigEndian.Uint16(msg)
					len := binary.BigEndian.Uint16(msg[2:])
					chmsg.data = make([]byte, len)
					copy(chmsg.data, msg[4:4+len])
					relay.inputMessage(&chmsg)
				}
			}
			continue
		}

		s.stunServerInput(msg[0:n], remoteaddr, s.conn.LocalAddr())
	}
}

func (s *STUNServer) stunServerInput(packet []byte, remoteaddr net.Addr, localaddr net.Addr) {

	var req STUNRequest
	req.msg.decode(packet, func(attrtype AttributeType, v []byte) {
		switch attrtype {
		case USERNAME:
			req.cred.username = v
		case REALM:
			req.cred.relam = v
		case NONCE:
			req.cred.nonce = v
		case PASSWORD:
			req.cred.password = v
		}
	})
	req.local = localaddr
	req.remote = remoteaddr
	if req.msg.method == STUN_METHOD_BINDING {
		req.authTerm = s.stun_term
	} else {
		req.authTerm = s.term
	}
	req.version = s.version
	req.data = packet

	switch req.msg.msgclass {
	case REQUEST:
		if err := s.stunAuthCheck(req); err != nil {
			fmt.Println(err)
			return
		}
		s.onRequest(req)
	case INDICATION:
		s.onIndication(req)
	default:
		panic("Error Class Type")
	}
}

func (s *STUNServer) onRequest(req STUNRequest) {
	switch req.msg.method {
	case STUN_METHOD_BINDING:
		s.stunOnBind(req)
	case STUN_METHOD_SHAREDSECRET:
		s.stunOnSharedSecret(req)
	case STUN_METHOD_ALLOCATE:
		s.stunOnAllocated(req)
	case STUN_METHOD_REFRESH:
		s.stunOnRefresh(req)
	case STUN_METHOD_CREATEPERMISSION:
		s.stunOnCreatePermission(req)
	case STUN_METHOD_CHANNELBIND:
		s.stunOnChannelBind(req)
	}
}

func (s *STUNServer) onIndication(req STUNRequest) {
	switch req.msg.method {
	case STUN_METHOD_BINDING:
		if s.OnBindIndication != nil {
			s.OnBindIndication(req)
		}
	case STUN_METHOD_SEND:
		s.stunOnSend(req)
	}
}

func (s *STUNServer) stunOnBind(req STUNRequest) {

	if s.OnBind != nil {
		if err := s.OnBind(req); err != nil {
			s.stunErrorResponse(req, 400, "Bad Request")
			return
		}
	}
	var msg STUNMessage

	msg.msgclass = SUCCESSRESPONSE
	msg.method = STUN_METHOD_BINDING
	msg.transactionId = req.msg.transactionId
	ip, port, _ := net.SplitHostPort(req.remote.String())
	ipbytes := net.ParseIP(ip).To4()
	portnumber, _ := strconv.Atoi(port)
	localIp, locaPort, _ := net.SplitHostPort(req.local.String())
	localipbytes := net.ParseIP(localIp)
	localPortNumber, _ := strconv.Atoi(locaPort)

	msg.addMapAddress(ipbytes, uint16(portnumber), IPV4)
	msg.addSourceAddress(localipbytes, uint16(localPortNumber), IPV4)
	msg.addXORMapAddress(ipbytes, uint16(portnumber), IPV4)
	msg.addResponseOriginAddress(localipbytes, uint16(localPortNumber), IPV4)
	s.stunReponse(msg, req.remote)
}

func (s *STUNServer) stunOnSharedSecret(req STUNRequest) {
	if s.OnSharedSecret != nil {
		if user, pwd, err := s.OnSharedSecret(req); err != nil {
			s.stunErrorResponse(req, 400, "Bad Request")
		} else {
			s.stunSharedSecretResponse(req, user, pwd)
		}
	}
}

//client--->turn-server--->relay--->peer
func (s *STUNServer) stunOnSend(req STUNRequest) {
	fmt.Println("on Send Indication")
	a, found := manager.findAllocatiionByTurnAddress(req.local, req.remote, 0)
	if found != nil {
		fmt.Println("Not Found Allocation")
		return
	}

	host, port, err := req.msg.readXORAddress(XOR_PEER_ADDRESS)
	if err != nil {
		fmt.Println("Not Exist xor Address")
		return
	}
	relay, found := fetchRelayConn(a.addr.relay[0].String())
	if found != nil {
		fmt.Println("Not Found relay")
		return
	}
	attr, _ := req.msg.findAttr(DATA)
	fmt.Println(host)
	fmt.Println(port)
	var msg relayIndicationMessage
	msg.peer, _ = net.ResolveUDPAddr("udp4", host+":"+strconv.Itoa(int(port)))
	msg.data = make([]byte, attr.length)
	copy(msg.data, attr.value[0:attr.length])
	fmt.Println("on Send Indication input message")
	relay.inputMessage(&msg)
}

//RFC5766 6.2.  Receiving an Allocate Request
func (s *STUNServer) stunOnAllocated(req STUNRequest) {

	allocate, err := manager.findAllocatiionByTurnAddress(req.local, req.remote, 0)
	if err == nil && time.Now().After(allocate.expire) {
		s.stunErrorResponse(req, ALLOCATIONMISMATCH, "Allocation Mismatch")
		return
	}

	a, err := req.msg.findAttr(REQUESTED_TRANSPORT)
	if err == nil && a.value[0] != UDP_TRANSPORT {
		s.stunErrorResponse(req, UNSUPPORT_TRANSPORT_PROTOCOL, "Unsupported Transport Protocol")
		return
	}

	evenport, evenportErr := req.msg.findAttr(EVEN_PORT)
	lifetime, lifetimeErr := req.msg.findAttr(LIFETIME)
	_, fragmentErr := req.msg.findAttr(DONT_FRAGMENT)

	family, familyError := req.msg.findAttr(REQUESTED_ADDRESS_FAMILY)

	if familyError == nil {
		if family.value[0] != 0x01 && family.value[0] != 0x02 {
			s.stunErrorResponse(req, ADDRESSFAMILYNOTSUPPORT, "Address Family not Supported")
			return
		}
	}

	reservedToken, reserveErr := req.msg.findAttr(RESERVATION_TOKEN)
	if reserveErr == nil {
		if evenportErr != nil {
			s.stunErrorResponse(req, BadRequest, "Bad Request")
			return
		}

		a, err := manager.findReservedAllocationByToken(reservedToken.value)
		if err != nil { //discard silent
			return
		}

		if time.Now().After(a.expire) {
			s.stunErrorResponse(req, INSUFFICIENTCAPACITY, "Insufficient Capacity")
			return
		}

		// 600 <= lifetime <= 3600
		if lifetimeErr != nil {
			a.lifeTime = TURN_LIFTTIME
		} else {
			a.lifeTime = binary.BigEndian.Uint32(lifetime.value)
			if a.lifeTime < TURN_LIFTTIME {
				a.lifeTime = TURN_LIFTTIME
			} else if a.lifeTime > 3600 {
				a.lifeTime = 3600
			}
		}

		a.expire = time.Now().Add(time.Second * time.Duration(a.lifeTime))
		if fragmentErr == nil {
			a.dontfragment = 1
		} else {
			a.dontfragment = 0
		}

		a.addr.local = req.local
		a.addr.remote = req.remote
		manager.removeReservedAllocationByToken(reservedToken.value)
		manager.addAllocation(a)
		s.responseAllocated(req, a)
	} else if s.OnAllocated != nil {
		allocate := TurnAllocation{
			reserveNextHigerPort: -1,
			dontfragment:         0,
			channels:             list.New(),
			permissions:          list.New(),
		}
		allocate.auth.nonce = make([]byte, len(req.cred.nonce))
		copy(allocate.auth.nonce, req.cred.nonce)
		allocate.auth.username = make([]byte, len(req.cred.username))
		copy(allocate.auth.username, req.cred.username)
		allocate.auth.password = make([]byte, len(req.cred.password))
		copy(allocate.auth.password, req.cred.password)
		allocate.auth.relam = make([]byte, len(req.cred.relam))
		copy(allocate.auth.relam, req.cred.relam)
		if evenportErr == nil {
			allocate.reserveNextHigerPort = int(evenport.value[0] & 0x80 >> 7)
		}

		// 600 <= lifetime <= 3600
		if lifetimeErr != nil {
			allocate.lifeTime = TURN_LIFTTIME
		} else {
			allocate.lifeTime = binary.BigEndian.Uint32(lifetime.value)
			if allocate.lifeTime < TURN_LIFTTIME {
				allocate.lifeTime = TURN_LIFTTIME
			} else if allocate.lifeTime > 3600 {
				allocate.lifeTime = 3600
			}
		}
		allocate.expire = time.Now().Add(time.Second * time.Duration(allocate.lifeTime))
		if fragmentErr == nil {
			allocate.dontfragment = 1
		} else {
			allocate.dontfragment = 0
		}
		if pr, err := s.OnAllocated(allocate.reserveNextHigerPort); err != nil {
			s.stunErrorResponse(req, INSUFFICIENTCAPACITY, "Insufficient Capacity")
		} else {
			for _, c := range pr {
				relay := newRelayConn(c)
				relay.allocate = &allocate
				relay.server = s
				relay.start()
				addRelayConn(c.LocalAddr().String(), relay)
				allocate.addr.relay = append(allocate.addr.relay, c.LocalAddr())
			}
			allocate.addr.local = req.local
			allocate.addr.remote = req.remote
			allocate.addr.protocol = 0
			manager.addAllocation(&allocate)
			fmt.Println(allocate.expire.String())
			s.responseAllocated(req, &allocate)
		}
	} else {
		return
	}

}

func (s *STUNServer) stunOnRefresh(req STUNRequest) {
	fmt.Println("on refresh")
	a, found := manager.findAllocatiionByTurnAddress(req.local, req.remote, 0)
	if found != nil {
		s.stunErrorResponse(req, ALLOCATIONMISMATCH, "Allocation Mismatch")
		return
	}
	var lifetime uint32 = 0
	attr, found := req.msg.findAttr(LIFETIME)
	if found == nil {
		lifetime = binary.BigEndian.Uint32(attr.value)
	}
	if lifetime == 0 {
		manager.removeAllocation(a)
	} else {
		if lifetime < TURN_LIFTTIME {
			lifetime = TURN_LIFTTIME
		} else if lifetime > 3600 {
			lifetime = 3600
		}
		a.lifeTime = lifetime
		a.expire = time.Now().Add(time.Second * time.Duration(lifetime))
		if s.OnRefresh != nil {
			s.OnRefresh(req.local, req.remote, 0, int(lifetime))
		}
	}
	var msg STUNMessage
	msg.msgclass = SUCCESSRESPONSE
	msg.method = STUN_METHOD_REFRESH
	msg.transactionId = req.msg.transactionId
	msg.addCredentials(req.authTerm, req.cred)
	msg.addFingerprint()
	s.stunReponse(msg, req.remote)
}

func (s *STUNServer) stunOnCreatePermission(req STUNRequest) {
	a, found := manager.findAllocatiionByTurnAddress(req.local, req.remote, 0)
	if found != nil {
		s.stunErrorResponse(req, ALLOCATIONMISMATCH, "Allocation Mismatch")
		return
	}

	host, _, err := req.msg.readXORAddress(XOR_PEER_ADDRESS)

	if err != nil {
		s.stunErrorResponse(req, INSUFFICIENTCAPACITY, "Insufficient Capacity")
	}

	p, ok := a.findTurnPermissionByHost(host)
	if ok {
		p.expired = time.Now().Add(time.Second * time.Duration(a.lifeTime))
		return
	}

	permission := &TurnPermissions{
		ip:      host,
		expired: time.Now().Add(time.Second * time.Duration(a.lifeTime)),
	}
	a.addTurnPermission(permission)
	var msg STUNMessage
	msg.msgclass = SUCCESSRESPONSE
	msg.method = STUN_METHOD_CREATEPERMISSION
	msg.transactionId = req.msg.transactionId
	msg.addCredentials(req.authTerm, req.cred)
	msg.addFingerprint()
	s.stunReponse(msg, req.remote)
}

func (s *STUNServer) stunOnChannelBind(req STUNRequest) {
	fmt.Println("on Channel Binding")
	a, found := manager.findAllocatiionByTurnAddress(req.local, req.remote, 0)
	if found != nil {
		s.stunErrorResponse(req, ALLOCATIONMISMATCH, "Allocation Mismatch")
		return
	}
	_, foundpeer := req.msg.findAttr(XOR_PEER_ADDRESS)
	channel, foundchannel := req.msg.findAttr(CHANNEL_NUMBER)
	channelnumber := binary.BigEndian.Uint16(channel.value)

	if foundpeer != nil || foundchannel != nil || channelnumber < 0x4000 || channelnumber > 0x7FFE {
		s.stunErrorResponse(req, BadRequest, "Bad Request")
		return
	}

	host, port, _ := req.msg.readXORAddress(XOR_PEER_ADDRESS)
	p, ok := a.findTurnPermissionByHost(host)
	if ok {
		p.expired = time.Now().Add(time.Second * time.Duration(a.lifeTime))
	} else {
		permission := &TurnPermissions{
			ip:      host,
			expired: time.Now().Add(time.Second * time.Duration(a.lifeTime)),
		}
		a.addTurnPermission(permission)
	}

	turnchannel, ok := a.findTurnChannel(channelnumber)
	if ok {
		if turnchannel.ip != host || turnchannel.port != strconv.Itoa(int(port)) {
			return
		}
		turnchannel.expired = time.Now().Add(time.Second * time.Duration(a.lifeTime))
	} else {
		if a.channels.Len() >= MAX_TURN_CAHNNEL_NUM {
			s.stunErrorResponse(req, INSUFFICIENTCAPACITY, "Insufficient Capacity")
			return
		}
		turnchannel = &TurnChannel{
			ip:      host,
			port:    strconv.Itoa(int(port)),
			channel: channelnumber,
			expired: time.Now().Add(time.Second * time.Duration(a.lifeTime)),
		}
		a.addTurnChannel(turnchannel)
		if s.OnChannel != nil {
			s.OnChannel(req.remote, host, port, int(channelnumber))
		}
	}
	var resmsg STUNMessage
	resmsg.msgclass = SUCCESSRESPONSE
	resmsg.method = STUN_METHOD_CHANNELBIND
	resmsg.transactionId = req.msg.transactionId
	resmsg.addCredentials(req.authTerm, req.cred)
	resmsg.addFingerprint()
	fmt.Println("channel bind response")
	s.stunReponse(resmsg, req.remote)
}

func (s *STUNServer) responseAllocated(req STUNRequest, allocate *TurnAllocation) {
	var msg STUNMessage
	msg.transactionId = req.msg.transactionId
	msg.msgclass = SUCCESSRESPONSE
	msg.method = STUN_METHOD_ALLOCATE
	msg.addLifeTime(allocate.lifeTime)
	msg.addXORAddressByAddr(XOR_MAPPED_ADDRESS, req.remote, IPV4)
	_, port, _ := net.SplitHostPort(allocate.addr.relay[0].String())
	tmprelay, _ := net.ResolveUDPAddr("udp4", s.publicIp+":"+port)
	msg.addXORAddressByAddr(XOR_RELAYED_ADDRESS, tmprelay, IPV4)
	if req.authTerm != STUN_ZERO_TERM {
		msg.addCredentials(req.authTerm, req.cred)
	}
	msg.addFingerprint()
	if len(allocate.token) > 0 {
		msg.addReservationToken(allocate.token)
	}
	s.stunReponse(msg, req.remote)
}

func (s *STUNServer) reponseChannelData(data []byte, peer net.Addr) {
	s.conn.WriteTo(data, peer)
}

func (s *STUNServer) stunAuthCheck(req STUNRequest) error {

	if req.authTerm == STUN_LONG_TERM {
		return s.stunLongAuthCheck(req)
	} else if req.authTerm == STUN_SHORT_TERM {
		return s.stunShortAuthCheck(req)
	} else {
		return nil
	}
}

func (s *STUNServer) stunLongAuthCheck(req STUNRequest) error {
	var res STUNResponse
	res.remote = req.remote
	_, err := req.msg.findAttr(MESSAGE_INTEGRITY)
	if err != nil {
		if s.GetNonce == nil {
			panic("must set GetNonce CallBack")
		}
		if relam, nonce, err2 := s.GetNonce(); err2 == nil {
			s.stunAuthResponse(req, 401, "Unauthorized", relam, nonce)
		} else {
			s.stunErrorResponse(req, 400, "Bad Request")
		}
		return err
	}

	if req.cred.username == nil || len(req.cred.username) <= 0 || req.cred.nonce == nil || len(req.cred.nonce) <= 0 || req.cred.relam == nil || len(req.cred.relam) <= 0 {
		s.stunErrorResponse(req, 400, "Bad Request")
		return errors.New("missing USERNAME REALM or NONCE")
	}

	if s.OnAuth == nil {
		panic("must set OnAuth CallBack")
	}

	if req.cred.password, err = s.OnAuth(req.authTerm, req.cred.username, req.cred.relam, req.cred.nonce); err != nil {
		s.stunErrorResponse(req, 438, "Stale Nonce")
		return err
	}

	if err = checkMessageIntegrity(req); err != nil {
		fmt.Println("checkMessageIntegrity failed")
		s.stunAuthResponse(req, 401, "Unauthorized", req.cred.relam, req.cred.nonce)
		return err
	}

	return nil
}

func (s *STUNServer) stunShortAuthCheck(req STUNRequest) error {
	_, err := req.msg.findAttr(MESSAGE_INTEGRITY)
	if err != nil && (req.cred.username == nil || len(req.cred.username) == 0) {
		s.stunErrorResponse(req, 400, "Bad Request")
		return err
	}

	if err != nil || req.cred.username == nil || len(req.cred.username) == 0 {
		s.stunErrorResponse(req, 401, "Unauthorized")
		if err == nil {
			return errors.New("Need UserName Attribute")
		}
		return err
	}

	if req.cred.password, err = s.OnAuth(req.authTerm, req.cred.username, req.cred.relam, req.cred.nonce); err != nil {
		s.stunErrorResponse(req, 401, "Unauthorized")
		return err
	}

	if err = checkMessageIntegrity(req); err != nil {
		s.stunAuthResponse(req, 401, "Unauthorized", req.cred.relam, req.cred.nonce)
		return err
	}

	return nil
}

func (s *STUNServer) stunReponse(msg STUNMessage, remote net.Addr) {
	if msg, err := msg.encode(); err == nil {
		s.conn.WriteTo(msg, remote)
	}
}

func (s *STUNServer) stunAuthResponse(req STUNRequest, code int, pharse string, realm []byte, nonce []byte) {
	var msg STUNMessage
	msg.transactionId = req.msg.transactionId
	msg.addErrorResponse(req.msg.method, code, pharse)
	if realm != nil && len(realm) > 0 {
		msg.addAttribute(REALM, realm)
	}
	if nonce != nil && len(nonce) > 0 {
		msg.addAttribute(NONCE, nonce)
	}
	s.stunReponse(msg, req.remote)
}

func (s *STUNServer) stunSharedSecretResponse(req STUNRequest, username []byte, pwd []byte) {

	var msg STUNMessage
	msg.transactionId = req.msg.transactionId
	msg.msgclass = SUCCESSRESPONSE
	msg.method = STUN_METHOD_SHAREDSECRET
	if username != nil && len(username) > 0 {
		msg.addAttribute(USERNAME, username)
	}
	if pwd != nil && len(pwd) > 0 {
		msg.addAttribute(PASSWORD, pwd)
	}
	s.stunReponse(msg, req.remote)
}

func (s *STUNServer) stunErrorResponse(req STUNRequest, code int, pharse string) {
	var msg STUNMessage
	msg.transactionId = req.msg.transactionId
	msg.addErrorResponse(req.msg.method, code, pharse)
	s.stunReponse(msg, req.remote)
}
