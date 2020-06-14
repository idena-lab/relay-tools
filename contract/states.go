package contract

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/idena-lab/bls-256-go"
	"github.com/idena-network/idena-go/common"
	"math/big"
	"math/rand"
	"os"
	"sort"
)

func NewIdentity(sk *big.Int) *identity {
	priKey, _ := bls.NewPriKey(new(big.Int).Set(sk))
	addr := common.Address{}
	rand.Read(addr[:])
	return &identity{
		addr: addr,
		pri:  priKey,
		pub1: priKey.GetPub1(),
		pub2: priKey.GetPub2(),
	}
}

type idenaStateManager struct {
	ids    identities
	pool   identities
	root   common.Hash
	height int
}

// make generated data more similar
var nextPrivateKey = bls.BigFromBase10("666666666666666666666666666666666666666666666666666666666666")

// get n identities from pool
// the removed identities in the pool may be returned
// return the slice of the new identities
func (m *idenaStateManager) getIdsFromPool(n int) identities {
	if len(m.pool) < n {
		for i := 0; i < n; i++ {
			m.pool = append(m.pool, NewIdentity(nextPrivateKey))
			nextPrivateKey = nextPrivateKey.Add(nextPrivateKey, big.NewInt(1))
		}
	}
	// randomly select ids from the pool
	rand.Shuffle(len(m.pool), func(i, j int) {
		m.pool[i], m.pool[j] = m.pool[j], m.pool[i]
	})
	ret := append(identities{}, m.pool[len(m.pool)-n:]...)
	m.pool = m.pool[:len(m.pool)-n]
	// sort by addresses (same as implement in idena-go)
	sort.Slice(ret, func(i, j int) bool {
		return bytes.Compare(ret[i].addr[:], ret[j].addr[:]) == 1
	})
	return ret
}

// change the set of active identities
// the rmCount identities to remove are selected randomly
// the removed identities will be appended to pool (used to test reused identities)
// returns the bit set of the removed indexes, the slice of new identities added
func (m *idenaStateManager) changeIds(rmCount, addCount int) ([]byte, identities) {
	if rmCount < 0 || rmCount > len(m.ids) {
		panic(fmt.Errorf("try to remove %d from %d ids", rmCount, len(m.ids)))
	}
	newIds := m.getIdsFromPool(addCount)
	// randomly select indexes to remove
	flags := make([]byte, (len(m.ids)+7)/8)
	rmIndexes := rand.Perm(len(m.ids))[:rmCount]
	sort.Ints(rmIndexes)
	// do the remove and add
	// the removed slots be filled by the new id first
	inserted := 0
	empties := make([]int, 0)
	for i := 0; i < rmCount; i++ {
		pos := rmIndexes[i]
		flags[pos/8] |= 1 << (pos % 8)
		m.pool = append(m.pool, m.ids[pos])
		if inserted < len(newIds) {
			m.ids[pos] = newIds[inserted]
			inserted++
		} else {
			empties = append(empties, pos)
		}
	}
	// the remaining new ids will be appended if `addCount > rmCount`
	// the remaining removed slots will be filled by the latter ids from the end if `addCount < rmCount`
	if inserted < len(newIds) {
		m.ids = append(m.ids, newIds[inserted:]...)
	} else {
		moving := len(m.ids) - 1
		for head, tail := 0, len(empties)-1; head <= tail; head++ {
			for ; moving == empties[tail] && moving >= empties[head]; moving-- {
				tail--
			}
			if moving >= empties[head] {
				m.ids[empties[head]] = m.ids[moving]
				moving--
			} else {
				break
			}
		}
		m.ids = m.ids[:moving+1]
	}
	return flags, newIds
}

func (m *idenaStateManager) clone() *idenaStateManager {
	cloned := &idenaStateManager{
		ids:    make(identities, len(m.ids)),
		pool:   make(identities, len(m.pool)),
		root:   common.Hash{},
		height: m.height,
	}
	copy(cloned.ids, m.ids)
	copy(cloned.pool, m.pool)
	copy(cloned.root[:], m.root[:])
	return cloned
}

func (m *idenaStateManager) reset(o *idenaStateManager) {
	if o == nil {
		return
	}
	m.ids = o.ids
	m.pool = o.pool
	m.root = o.root
	m.height = o.height
}

func (m *idenaStateManager) quorum() int {
	return (m.population()*2-1)/3 + 1
}

func (m *idenaStateManager) population() int {
	return len(m.ids)
}

// collect signers with the bit set flags
func (m *idenaStateManager) randomSigners(n int) (identities, []byte) {
	if n < 0 {
		panic("at least one singer is required")
	}
	signers := make(identities, n)
	flags := make([]byte, (len(m.ids)+7)/8)
	r := rand.Perm(len(m.ids))
	// make the first n indexes as signer indexes
	for i := 0; i < n; i++ {
		signers[i] = m.ids[r[i]]
		flags[r[i]/8] |= 1 << (r[i] % 8)
	}
	return signers, flags
}

func (m *idenaStateManager) updateRoot(newIds identities, rmFlags []byte) {
	hIds := common.Hash{}
	for _, id := range newIds {
		xy := bls.PointToInt1(id.pub1.GetPoint())
		bytes := append(hIds[:], id.addr[:]...)
		bytes = append(bytes, bls.BigToBytes(xy[0], 32)...)
		bytes = append(bytes, bls.BigToBytes(xy[1], 32)...)
		copy(hIds[:], bls.Keccak256(bytes))
	}
	bytes := append(m.root[:], bls.BigToBytes(big.NewInt(int64(m.height)), 32)...)
	bytes = append(bytes, hIds[:]...)
	bytes = append(bytes, bls.Keccak256(rmFlags)...)
	copy(m.root[:], bls.Keccak256(bytes))
}

// sign and aggregate signatures
func (m *idenaStateManager) aggSign(signers identities) (*bls.Signature, *bls.PubKey2) {
	sigs := make([]*bls.Signature, len(signers))
	pub2s := make([]*bls.PubKey2, len(signers))
	for i, id := range signers {
		sigs[i] = id.pri.Sign(m.root[:])
		pub2s[i] = id.pub2
	}
	return bls.AggregateSignatures(sigs), bls.AggregatePubKeys2(pub2s)
}

func (m *idenaStateManager) getCheckState(valid bool) *idenaCheckState {
	pop := len(m.ids)
	return &idenaCheckState{
		Height:     m.height,
		Valid:      valid,
		Population: pop,
		StateRoot:  "0x" + hex.EncodeToString(m.root[:]),
		FirstId:    m.ids[0].toState(),
		LastId:     m.ids[pop-1].toState(),
		MiddleId:   m.ids[pop/2].toState(),
	}
}

func (m *idenaStateManager) doUpdate(valid bool, height int, enoughSigner bool, rmCount, addCount int) *idenaUpdateState {
	signCount := m.quorum() + rand.Intn(m.population()-m.quorum()) + 1
	if !enoughSigner {
		signCount = rand.Intn(m.quorum()-1) + 1
	}

	origin := m.clone()
	m.height = height
	signers, signFlags := m.randomSigners(signCount)
	rmFlags, newIds := m.changeIds(rmCount, addCount)

	m.updateRoot(newIds, rmFlags)
	signature, apk2 := m.aggSign(signers)
	// check signature
	if !bls.Verify(m.root[:], signature, apk2) {
		panic("verify failed")
	}
	// check state
	if len(origin.ids)-rmCount+addCount != len(m.ids) {
		panic("remain identity count not right")
	}

	comment := fmt.Sprintf(
		"height(%d): %d identities -%d +%d by %d signers(%.2f%%)",
		height, len(origin.ids), rmCount, addCount, signCount, float64(signCount)*100/float64(origin.population()),
	)
	u := &idenaUpdateState{
		Comment:       comment,
		Height:        height,
		NewIdentities: newIds.getAddresses(),
		NewPubKeys:    newIds.getPubKeys(),
		RemoveFlags:   rmFlags,
		RemoveCount:   rmCount,
		SignFlags:     signFlags,
		Signature:     signature.ToHex(),
		Apk2:          apk2.ToHex(),
		Checks:        nil,
	}

	isValidUpdate := height > origin.height && signCount >= origin.quorum()
	if valid != isValidUpdate {
		panic(fmt.Errorf("validation error for %s", u.Comment))
	}
	if !isValidUpdate {
		m.reset(origin)
	}
	u.Checks = m.getCheckState(isValidUpdate)
	fmt.Printf("Active identities: %v\n", len(m.ids))
	return u
}

// generate test cases for init() and update() in contract
func GenTestsForStateChanges(f *os.File) {
	initHeight := 12345678
	initPop := 2000
	m := &idenaStateManager{
		height: initHeight,
		pool:   make(identities, 0, 10000),
		ids:    make(identities, 0),
		root:   common.Hash{},
	}
	m.ids = m.getIdsFromPool(initPop)
	m.updateRoot(m.ids, []byte{})
	// println(m.root.String())

	data := &idenaTestData{}
	data.Init = &idenaInitState{
		Comment:    fmt.Sprintf("epcoch(%d): init with %v identities", m.height, m.population()),
		Height:     initHeight,
		Identities: m.ids.getAddresses(),
		PubKeys:    m.ids.getPubKeys(),
		Checks:     m.getCheckState(true),
	}
	data.Updates = make([]*idenaUpdateState, 0)

	// case1
	data.Updates = append(data.Updates,
		m.doUpdate(true, m.height+1, true, 0, 0),
		m.doUpdate(true, m.height+1, true, 100, 0),
		m.doUpdate(true, m.height+2, true, 0, 100),
		m.doUpdate(true, m.height+1, true, 125, 173),
		m.doUpdate(true, m.height+2, true, 186, 145),
		m.doUpdate(true, m.height+4, true, 210, 180),
		m.doUpdate(true, m.height+1, true, 180, 200),
		// invalid cases
		m.doUpdate(false, m.height, true, 100, 120),
		m.doUpdate(false, m.height-1, true, 100, 120),
		m.doUpdate(false, m.height+1, false, 100, 120),
		// valid again
		m.doUpdate(true, m.height+1, true, 80, 110),
	)

	// case2
	// add 1000 identities
	// data.Updates = append(data.Updates,
	// 	m.doUpdate(true, m.height+1, true, 100, 0),
	// 	m.doUpdate(true, m.height+1, true, 100, 100),
	// 	m.doUpdate(true, m.height+1, true, 100, 200),
	// 	m.doUpdate(true, m.height+1, true, 200, 100),
	// 	m.doUpdate(true, m.height+1, true, 200, 200),
	// 	m.doUpdate(true, m.height+1, true, 300, 100),
	// 	m.doUpdate(true, m.height+1, true, 300, 200),
	// 	// out of gas
	// 	m.doUpdate(true, m.height+1, true, 300, 250),
	// 	// m.doUpdate(true, m.height+1, true, 100, 300),
	// 	// m.doUpdate(true, m.height+1, true, 200, 300),
	// 	// m.doUpdate(true, m.height+1, true, 300, 300),
	// )

	jd, _ := json.MarshalIndent(data, "", "  ")
	_, _ = f.Write(jd)
	fmt.Printf("\n> Data has written to %v\n", f.Name())
}
