package goturn

import "net"

type CredentialsInfo struct {
	username []byte
	relam    []byte
	nonce    []byte
	password []byte
}

type STUN_VERSION int

const (
	RFC_3489 STUN_VERSION = 0
	RFC_5389              = 1
)

type AUTH_TERM int

const (
	STUN_ZERO_TERM  AUTH_TERM = 0
	STUN_LONG_TERM            = 1
	STUN_SHORT_TERM           = 2
)

type STUNRequest struct {
	msg      STUNMessage
	cred     CredentialsInfo
	version  STUN_VERSION
	authTerm AUTH_TERM
	remote   net.Addr
	local    net.Addr
	data     []byte
}

type STUNResponse struct {
	remote net.Addr
	msg    STUNMessage
}

func (r STUNRequest) GetRemoteAddr() net.Addr {
	return r.remote
}

func (r STUNRequest) GetLocalAddr() net.Addr {
	return r.local
}

func (r STUNRequest) GetAuth() (username string, relam string, nonce string, pwd string) {
	username = string(r.cred.username)
	relam = string(r.cred.relam)
	nonce = string(r.cred.nonce)
	pwd = string(r.cred.password)
	return
}
