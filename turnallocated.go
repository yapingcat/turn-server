package goturn

import (
	"bytes"
	"container/list"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

type TurnAddress struct {
	local    net.Addr
	remote   net.Addr
	relay    []net.Addr
	protocol int //0: udp 1:tcp 2:tls
}

type TurnPermissions struct {
	expired time.Time
	ip      string
}

const MAX_TURN_CAHNNEL_NUM = 8

type TurnChannel struct {
	ip      string
	port    string
	channel uint16
	expired time.Time
}

type TurnAllocation struct {
	addr                 TurnAddress
	expire               time.Time
	lifeTime             uint32
	reserveNextHigerPort int
	token                []byte
	dontfragment         int
	auth                 CredentialsInfo
	permissions          *list.List
	channels             *list.List
	mtx                  sync.Mutex
}

func (a *TurnAllocation) findTurnChannel(channel uint16) (*TurnChannel, bool) {
	a.mtx.Lock()
	defer a.mtx.Unlock()
	for e := a.channels.Front(); e != nil; e = e.Next() {
		if ch, ok := e.Value.(*TurnChannel); ok {
			if ch.channel == channel {
				return ch, true
			}
		}
	}
	return nil, false
}

func (a *TurnAllocation) findTurnChannelByAddr(addr net.Addr) (*TurnChannel, bool) {
	a.mtx.Lock()
	defer a.mtx.Unlock()
	host, port, _ := net.SplitHostPort(addr.String())
	for e := a.channels.Front(); e != nil; e = e.Next() {
		if ch, ok := e.Value.(*TurnChannel); ok {
			if ch.ip == host && ch.port == port {
				return ch, true
			}
		}
	}
	return nil, false
}

func (a *TurnAllocation) addTurnChannel(channel *TurnChannel) {
	a.mtx.Lock()
	defer a.mtx.Unlock()
	a.channels.PushBack(channel)
}

func (a *TurnAllocation) addTurnPermission(premission *TurnPermissions) {
	a.mtx.Lock()
	defer a.mtx.Unlock()
	a.permissions.PushBack(premission)
}

func (a *TurnAllocation) findTurnPermissionByAddr(addr net.Addr) (*TurnPermissions, bool) {
	a.mtx.Lock()
	defer a.mtx.Unlock()
	host, _, _ := net.SplitHostPort(addr.String())
	for e := a.permissions.Front(); e != nil; e = e.Next() {
		if per, ok := e.Value.(*TurnPermissions); ok {
			if per.ip == host {
				return per, true
			}
		}
	}
	return nil, false
}

func (a *TurnAllocation) findTurnPermissionByHost(host string) (*TurnPermissions, bool) {
	a.mtx.Lock()
	defer a.mtx.Unlock()
	for e := a.permissions.Front(); e != nil; e = e.Next() {
		if per, ok := e.Value.(*TurnPermissions); ok {
			if per.ip == host {
				return per, true
			}
		}
	}
	return nil, false
}

type AllocationManager struct {
	mtx           sync.Mutex
	allocatedList *list.List
	reservedList  *list.List
}

var manager AllocationManager

func init() {
	manager.allocatedList = list.New()
	manager.reservedList = list.New()
	go manager.checkLiveness()
}

func (m *AllocationManager) addAllocation(a *TurnAllocation) {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	m.allocatedList.PushBack(a)
}

func (m *AllocationManager) findAllocatiionByTurnAddress(local net.Addr, remote net.Addr, protocol int) (*TurnAllocation, error) {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	for e := m.allocatedList.Front(); e != nil; e = e.Next() {
		a, ok := e.Value.(*TurnAllocation)
		if ok {
			if a.addr.local.String() == local.String() && a.addr.remote.String() == remote.String() && a.addr.protocol == protocol {
				return a, nil
			}
		}
	}
	return nil, errors.New("Not Found")
}

func (m *AllocationManager) removeAllocation(allocation *TurnAllocation) {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	for e := m.allocatedList.Front(); e != nil; e = e.Next() {
		a, ok := e.Value.(*TurnAllocation)
		if ok {
			if a == allocation {
				removeRelay(a.addr.relay[0].String())
				m.allocatedList.Remove(e)
				return
			}
		}
	}
}

func (m *AllocationManager) findReservedAllocationByToken(token []byte) (*TurnAllocation, error) {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	for e := m.reservedList.Front(); e != nil; e = e.Next() {
		a, ok := e.Value.(*TurnAllocation)
		if ok {
			if bytes.Compare(a.token, token) == 0 {
				return a, nil
			}
		}
	}
	return nil, errors.New("Not Found")
}

func (m *AllocationManager) removeReservedAllocationByToken(token []byte) {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	for e := m.reservedList.Front(); e != nil; e = e.Next() {
		a, ok := e.Value.(TurnAllocation)
		if ok {
			if bytes.Compare(a.token, token) == 0 {
				m.reservedList.Remove(e)
				return
			}
		}
	}
}

func (m *AllocationManager) checkLiveness() {
	for {
		m.mtx.Lock()
		fmt.Println("CheckLiveness")
		var next *list.Element
		for e := m.allocatedList.Front(); e != nil; e = next {
			a, ok := e.Value.(*TurnAllocation)
			if ok {
				if time.Now().After(a.expire) {
					next = e.Next()
					m.allocatedList.Remove(e)
					fmt.Println("Allocation is idle remote it" + a.addr.remote.String())
					continue
				}
			}
			next = e.Next()
		}

		for e := m.reservedList.Front(); e != nil; e = next {
			a, ok := e.Value.(TurnAllocation)
			if ok {
				if time.Now().After(a.expire) {
					next = e.Next()
					m.reservedList.Remove(e)
					continue
				}
			}
			next = e.Next()
		}
		m.mtx.Unlock()
		time.Sleep(time.Second * time.Duration(TURN_LIFTTIME))
	}
}
