package goturn

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"hash/crc32"
)

const FINGERPRINT_XOR uint32 = 0x5354554e

func genKey(username []byte, realm []byte, pwd []byte) [16]byte {
	data := make([]byte, 0, len(username)+len(realm)+len(pwd)+2)
	data = append(data, username...)
	data = append(data, ':')
	data = append(data, realm...)
	data = append(data, ':')
	data = append(data, pwd...)
	return md5.Sum(data)
}

func checkMessageIntegrity(req STUNRequest) error {
	if req.authTerm == STUN_ZERO_TERM {
		return nil
	}

	var key []byte
	if req.authTerm == STUN_SHORT_TERM {
		key = req.cred.password
	} else {
		tmp := genKey(req.cred.username, req.cred.relam, req.cred.password)
		key = tmp[:]
	}
	var integrity []byte
	excludelen := 0
	for i := len(req.msg.attrs) - 1; i >= 0; i-- {
		excludelen += int(align4Bytes(req.msg.attrs[i].length)) + 4
		if req.msg.attrs[i].attrtype == MESSAGE_INTEGRITY {
			integrity = req.msg.attrs[i].value
			break
		}
	}
	length := req.msg.length - uint16(excludelen) + 24
	mac := hmac.New(sha1.New, key[0:])
	lenbyte := make([]byte, 2)
	binary.BigEndian.PutUint16(lenbyte, length)
	mac.Write(req.data[0:2])
	mac.Write(lenbyte)
	mac.Write(req.data[4 : len(req.data)-excludelen])
	expectedMAC := mac.Sum(nil)
	if bytes.Compare(expectedMAC, integrity) == 0 {
		return nil
	} else {
		return errors.New("Hmac is not equal")
	}
}

func checkfingerprint(data []byte, msg STUNMessage) error {

	var fingerprint uint32
	excludelen := 0
	for i := len(msg.attrs) - 1; i >= 0; i-- {
		if msg.attrs[i].attrtype == FINGERPRINT {
			excludelen += 8
			fingerprint = binary.BigEndian.Uint32(msg.attrs[i].value)
			break
		}
		excludelen += int(msg.attrs[i].length) + 4
	}

	if excludelen == 0 {
		return errors.New("Not Found FINGERPRINT Attribute")
	}

	result := crc32.ChecksumIEEE(data[0 : len(data)-excludelen])
	result = result ^ FINGERPRINT_XOR
	if result == fingerprint {
		return nil
	}
	return errors.New("CRC32 CheckSum Failed")
}
