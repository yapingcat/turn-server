package goturn

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"net"
	"strconv"
)

type ErrorCode uint16

const (
	TryAlternate                 ErrorCode = 300
	BadRequest                             = 400
	UNAUTHORIZED                           = 401
	FORBIDDEN                              = 403
	UNKNOWNATTRIBUTES                      = 420
	ALLOCATIONMISMATCH                     = 437
	STALENONCE                             = 438
	ADDRESSFAMILYNOTSUPPORT                = 440
	WRONGCREDENTIALS                       = 441
	UNSUPPORT_TRANSPORT_PROTOCOL           = 442
	ALLOCATION_QUOTA_REACHED               = 486
	ServerError                            = 500
	INSUFFICIENTCAPACITY                   = 508
)

type AttributeType uint16

const (
	Reserved                 AttributeType = 0x0000
	MAPPED_ADDRESS                         = 0x0001
	RESPONSE_ADDRESS                       = 0x0002
	CHANGE_REQUEST                         = 0x0003 //RFC5780
	SOURCE_ADDRESS                         = 0x0004
	CHANGED_ADDRESS                        = 0x0005
	USERNAME                               = 0x0006
	PASSWORD                               = 0x0007
	MESSAGE_INTEGRITY                      = 0x0008
	ERROR_CODE                             = 0x0009
	UNKNOWN_ATTRIBUTES                     = 0x000A
	REFLECTED_FROM                         = 0x000B
	CHANNEL_NUMBER                         = 0x000C
	LIFETIME                               = 0x000D
	Reserved2                              = 0x0010 //(was BANDWIDTH)
	XOR_PEER_ADDRESS                       = 0x0012
	DATA                                   = 0x0013
	REALM                                  = 0x0014
	NONCE                                  = 0x0015
	XOR_RELAYED_ADDRESS                    = 0x0016
	REQUESTED_ADDRESS_FAMILY               = 0x0017 //rfc6156
	EVEN_PORT                              = 0x0018
	REQUESTED_TRANSPORT                    = 0x0019
	DONT_FRAGMENT                          = 0x001A
	XOR_MAPPED_ADDRESS                     = 0x0020
	Reserved3                              = 0x0021 //TIMER-VAL
	RESERVATION_TOKEN                      = 0x0022
	PADDING                                = 0x0026 //RFC5780
	RESPONSE_PORT                          = 0x0027 //RFC5780
	SOFTWARE                               = 0x8022
	ALTERNATE_SERVER                       = 0x8023
	CACHE_TIMEOUT                          = 0x8027 //RFC5780
	FINGERPRINT                            = 0x8028
	RESPONSE_ORIGIN                        = 0x802b //RFC5780
	OTHER_ADDRESS                          = 0x802c //RFC5780
)

var MAGIC_COOKIES uint32 = 0x2112A442
var UDP_TRANSPORT uint8 = 17
var TURN_LIFTTIME uint32 = 600

type STUNAttribute struct {
	attrtype AttributeType
	length   uint16
	value    []byte
}

func readXorAddress(attr STUNAttribute, transactionId [12]byte) (string, uint16, error) {
	if attr.attrtype != XOR_MAPPED_ADDRESS && attr.attrtype != XOR_PEER_ADDRESS && attr.attrtype != XOR_RELAYED_ADDRESS {
		return "", 0, errors.New("Attr Type Error")
	}

	var port uint16
	var host string
	var portbytes [2]byte
	if attr.value[1] == 0x01 {
		port = binary.BigEndian.Uint16(attr.value[2:4]) ^ uint16(MAGIC_COOKIES>>16)
		tmphost := binary.BigEndian.Uint32(attr.value[4:]) ^ uint32(MAGIC_COOKIES)
		hostByte := make([]byte, 4)
		binary.BigEndian.PutUint32(hostByte, tmphost)
		host = net.IP(hostByte).String()
	} else {

		port = binary.BigEndian.Uint16(attr.value[2:4]) ^ uint16(MAGIC_COOKIES>>16)
		binary.BigEndian.PutUint16(portbytes[:], port)
		port = nativeEndian.Uint16(portbytes[:])
		hostByte := make([]byte, 16)
		hostByte[0] = attr.value[4] ^ uint8(MAGIC_COOKIES>>24)
		hostByte[1] = attr.value[5] ^ uint8(MAGIC_COOKIES>>16)
		hostByte[2] = attr.value[6] ^ uint8(MAGIC_COOKIES>>8)
		hostByte[3] = attr.value[7] ^ uint8(MAGIC_COOKIES)

		for i := 8; i < 20; i++ {
			hostByte[i-4] = attr.value[i] ^ transactionId[i-8]
		}
		host = net.IP(hostByte).String()

	}

	return host, port, nil
}

type MessageClass int

const (
	REQUEST         MessageClass = 0x0000
	INDICATION                   = 0x0010
	SUCCESSRESPONSE              = 0x0100
	ERRORRESPONSE                = 0x0110
)

type STUNMethod int

const (
	STUN_METHOD_RESERVED         STUNMethod = 0x0000
	STUN_METHOD_BINDING                     = 0x0001
	STUN_METHOD_SHAREDSECRET                = 0x0002
	STUN_METHOD_ALLOCATE                    = 0x0003
	STUN_METHOD_REFRESH                     = 0x0004
	STUN_METHOD_SEND                        = 0x0006
	STUN_METHOD_DATA                        = 0x0007
	STUN_METHOD_CREATEPERMISSION            = 0x0008
	STUN_METHOD_CHANNELBIND                 = 0x0009
)

type STUNMessage struct {
	msgclass      MessageClass
	method        STUNMethod
	length        uint16
	transactionId [12]byte
	attrs         []STUNAttribute
}

// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |0 0|     STUN Message Type     |         Message Length        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                         Magic Cookie                          |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// |                     Transaction ID (96 bits)                  |
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

// 0                 1
// 2  3  4 5 6 7 8 9 0 1 2 3 4 5

// +--+--+-+-+-+-+-+-+-+-+-+-+-+-+
// |M |M |M|M|M|C|M|M|M|C|M|M|M|M|
// |11|10|9|8|7|1|6|5|4|0|3|2|1|0|
// +--+--+-+-+-+-+-+-+-+-+-+-+-+-+

func (m *STUNMessage) encode() ([]byte, error) {
	for _, attr := range m.attrs {
		m.length += align4Bytes(attr.length) + 4
	}
	stunmsg := make([]byte, m.length+20)
	msgtype := uint16(m.msgclass) | uint16(m.method)
	binary.BigEndian.PutUint16(stunmsg, msgtype)
	binary.BigEndian.PutUint16(stunmsg[2:], m.length)
	binary.BigEndian.PutUint32(stunmsg[4:], MAGIC_COOKIES)
	copy(stunmsg[8:], m.transactionId[:])

	idx := uint16(20)
	for _, attr := range m.attrs {
		if idx > m.length+20 {
			return nil, errors.New("STUN Message Length <  Total Message Length")
		}
		binary.BigEndian.PutUint16(stunmsg[idx:], uint16(attr.attrtype))
		binary.BigEndian.PutUint16(stunmsg[idx+2:], uint16(attr.length))
		copy(stunmsg[idx+4:], attr.value[:attr.length])
		idx = idx + 4 + align4Bytes(attr.length)
	}
	m.length = 0
	return stunmsg, nil
}

func (m *STUNMessage) decode(buf []byte, onAttr func(attrtype AttributeType, v []byte)) error {

	if len(buf) < 20 {
		return errors.New("Too Little Bytes")
	}

	msgtype := binary.BigEndian.Uint16(buf)
	if msgtype&0xC0 != 0x0000 {
		return errors.New("Error Format First 2 bits must be zero")
	}

	m.msgclass = MessageClass(msgtype & 0x0110)
	m.method = STUNMethod(msgtype & 0x3EEF)
	m.length = binary.BigEndian.Uint16(buf[2:])
	copy(m.transactionId[:], buf[8:20])
	if m.length+20 < uint16(len(buf)) {
		return errors.New("Too Little Bytes need more Attribute")
	}
	m.attrs = make([]STUNAttribute, 0, 8)
	idx := uint16(20)
	for idx < m.length+20 {
		attrlen := binary.BigEndian.Uint16(buf[idx+2:])
		attr := STUNAttribute{
			attrtype: AttributeType(binary.BigEndian.Uint16(buf[idx:])),
			length:   attrlen,
			value:    buf[idx+4 : idx+4+attrlen], // need deep copy?
		}
		if onAttr != nil {
			onAttr(attr.attrtype, attr.value)
		}
		m.attrs = append(m.attrs, attr)
		idx += 4 + align4Bytes(attr.length)
	}
	return nil
}

func (m *STUNMessage) addCredentials(term AUTH_TERM, cred CredentialsInfo) {

	var key []byte
	m.addAttribute(USERNAME, cred.username)
	if term == STUN_LONG_TERM {
		m.addAttribute(REALM, cred.relam)
		m.addAttribute(NONCE, cred.nonce)
		tmp := genKey(cred.username, cred.relam, cred.password)
		key = tmp[:]
	} else {
		key = cred.password
	}
	m.addMessageIntegrity(key)
}

func (m *STUNMessage) addMessageIntegrity(key []byte) {
	msg, _ := m.encode()
	mac := hmac.New(sha256.New, key)
	mac.Write(msg)
	expectedMAC := mac.Sum(nil)
	attr := STUNAttribute{
		attrtype: MESSAGE_INTEGRITY,
		length:   uint16(len(expectedMAC)),
		value:    expectedMAC,
	}
	m.attrs = append(m.attrs, attr)
}

func (m *STUNMessage) addFingerprint() {
	msg, _ := m.encode()
	v := crc32.ChecksumIEEE(msg)
	v ^= FINGERPRINT_XOR
	attr := STUNAttribute{
		attrtype: FINGERPRINT,
		length:   4,
		value:    make([]byte, 4),
	}
	binary.BigEndian.PutUint32(attr.value, v)
	m.attrs = append(m.attrs, attr)
}

func (m *STUNMessage) addResponseOriginAddress(host []byte, port uint16, addressType int) {
	m.addAddress(RESPONSE_ORIGIN, host, port, addressType)
}

func (m *STUNMessage) addSourceAddress(host []byte, port uint16, addressType int) {
	m.addAddress(SOURCE_ADDRESS, host, port, addressType)
}

func (m *STUNMessage) addMapAddress(host []byte, port uint16, addressType int) {
	m.addAddress(MAPPED_ADDRESS, host, port, addressType)
}

func (m *STUNMessage) addAddress(attrType AttributeType, host []byte, port uint16, addressType int) {
	var mapaddr []byte
	if addressType == IPV4 {
		mapaddr = make([]byte, 8)
		mapaddr[1] = 0x01
		binary.BigEndian.PutUint16(mapaddr[2:], port)
		copy(mapaddr[4:], host)
	} else {
		mapaddr = make([]byte, 20)
		mapaddr[1] = 0x02
		binary.BigEndian.PutUint16(mapaddr[2:], port)
		copy(mapaddr[4:], host)
	}
	m.addAttribute(attrType, mapaddr)
}

func (m *STUNMessage) addXORAddressByAddr(attrType AttributeType, addr net.Addr, addressType int) {
	ip, port, _ := net.SplitHostPort(addr.String())
	ipbytes := net.ParseIP(ip).To4()
	portnumber, _ := strconv.Atoi(port)
	m.addXORAddress(attrType, ipbytes, uint16(portnumber), addressType)
}

func (m *STUNMessage) addXORMapAddress(host []byte, port uint16, addressType int) {
	m.addXORAddress(XOR_MAPPED_ADDRESS, host, port, addressType)
}

func (m *STUNMessage) addXORAddress(attrType AttributeType, host []byte, port uint16, addressType int) {
	var xoraddr []byte
	if addressType == IPV4 {
		xoraddr = make([]byte, 8)
		xoraddr[1] = 0x01
		//	var portbyte [2]byte
		//binary.BigEndian.PutUint16(portbyte[0:], port)
		binary.BigEndian.PutUint16(xoraddr[2:], port^uint16(MAGIC_COOKIES>>16))
		var addr uint32
		addr = uint32(host[0])
		addr = addr<<8 | uint32(host[1])
		addr = addr<<8 | uint32(host[2])
		addr = addr<<8 | uint32(host[3])
		binary.BigEndian.PutUint32(xoraddr[4:], addr^uint32(MAGIC_COOKIES))
	} else {
		xoraddr = make([]byte, 20)
		xoraddr[1] = 0x02
		var portbyte [2]byte
		binary.BigEndian.PutUint16(portbyte[0:], port)
		binary.BigEndian.PutUint16(xoraddr[2:], binary.BigEndian.Uint16(portbyte[:])^uint16(MAGIC_COOKIES>>16))
		xoraddr[4] = host[0] ^ uint8(MAGIC_COOKIES>>24)
		xoraddr[5] = host[1] ^ uint8(MAGIC_COOKIES>>16)
		xoraddr[6] = host[2] ^ uint8(MAGIC_COOKIES>>8)
		xoraddr[7] = host[3] ^ uint8(MAGIC_COOKIES)

		for i := 8; i < 20; i++ {
			xoraddr[i] = host[i-4] ^ m.transactionId[i-8]
		}
	}
	m.addAttribute(attrType, xoraddr)
}

func (m *STUNMessage) addErrorResponse(mothed STUNMethod, code int, pharse string) {
	m.attrs = nil //clear all attribute
	//m.attrs = make([]STUNAttribute, 1)
	m.msgclass = ERRORRESPONSE
	m.method = mothed
	ec := make([]byte, 4+len(pharse))
	ec[2] = byte(code / 100)
	ec[3] = byte(code % 100)
	copy(ec[4:], []byte(pharse))
	m.addAttribute(ERROR_CODE, ec)
}

func (m *STUNMessage) addChannelNumber(chno int) {
	value := make([]byte, 4)
	binary.BigEndian.PutUint16(value[0:], uint16(chno))
	m.addAttribute(CHANNEL_NUMBER, value)
}

func (m *STUNMessage) addLifeTime(lifetime uint32) {
	value := make([]byte, 4)
	binary.BigEndian.PutUint32(value, lifetime)
	m.addAttribute(LIFETIME, value)
}

func (m *STUNMessage) addXORPeerAddress(host []byte, port uint16, addressType int) {
	m.addXORAddress(XOR_PEER_ADDRESS, host, port, addressType)
}

func (m *STUNMessage) addXORRelayAddress(host []byte, port uint16, addressType int) {
	m.addXORAddress(XOR_RELAYED_ADDRESS, host, port, addressType)
}

func (m *STUNMessage) addEVENPort(R int) {
	if R == 0 {
		var r byte = 0
		m.addAttribute(EVEN_PORT, r)
	} else {
		var r byte = 1
		m.addAttribute(EVEN_PORT, r)
	}
}

func (m *STUNMessage) addRequestTransport(protocol byte) {
	value := make([]byte, 4)
	value[0] = protocol
	m.addAttribute(REQUESTED_TRANSPORT, value)
}

func (m *STUNMessage) addDontFragment() {
	attr := STUNAttribute{
		attrtype: DONT_FRAGMENT,
		length:   0,
	}
	m.attrs = append(m.attrs, attr)
}

func (m *STUNMessage) addReservationToken(token []byte) {
	m.addAttribute(RESERVATION_TOKEN, token)
}

func (m *STUNMessage) addData(data []byte) {
	m.addAttribute(DATA, data)
}

func (m *STUNMessage) addAttribute(t AttributeType, v interface{}) {
	attr := STUNAttribute{
		attrtype: t,
	}
	switch value := v.(type) {
	case byte:
		attr.value = make([]byte, 1)
		attr.length = 1
		attr.value[0] = value
	case int:
		attr.value = make([]byte, 4)
		attr.length = 4
		binary.BigEndian.PutUint32(attr.value, uint32(value))
	case int64:
		attr.value = make([]byte, 8)
		attr.length = 8
		binary.BigEndian.PutUint64(attr.value, uint64(value))
	case uint16:
		attr.value = make([]byte, 2)
		attr.length = 2
		binary.BigEndian.PutUint16(attr.value, value)
	case uint32:
		attr.value = make([]byte, 4)
		attr.length = 4
		binary.BigEndian.PutUint32(attr.value, value)
	case uint64:
		attr.value = make([]byte, 8)
		attr.length = 8
		binary.BigEndian.PutUint64(attr.value, value)
	case []byte:
		attr.value = make([]byte, len(value))
		copy(attr.value, value)
		attr.length = uint16(len(attr.value))
	case string:
		attr.value = make([]byte, len(value))
		copy(attr.value, []byte(value))
		attr.length = uint16(len(attr.value))
	default:
		panic("unknow type")
	}
	m.attrs = append(m.attrs, attr)
}

func (m *STUNMessage) readXORAddress(attrtype AttributeType) (string, uint16, error) {
	attr, found := m.findAttr(attrtype)
	if found != nil {
		return "", 0, found
	}
	return readXorAddress(attr, m.transactionId)
}

func (m *STUNMessage) findAttr(t AttributeType) (STUNAttribute, error) {
	for _, attr := range m.attrs {
		if attr.attrtype == t {
			return attr, nil
		}
	}
	return STUNAttribute{}, errors.New("Not Found Attr")
}
