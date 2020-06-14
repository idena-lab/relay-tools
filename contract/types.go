package contract

import (
	"github.com/idena-lab/bls-256-go"
	"github.com/idena-network/idena-go/common"
	"github.com/idena-network/idena-go/common/hexutil"
)

type Bytes []byte

func (b Bytes) String() string {
	return hexutil.Encode(b)
}

func (b Bytes) MarshalText() ([]byte, error) {
	return []byte(b.String()), nil
}

type verifyItem struct {
	// count of keys aggregated
	Keys int `json:"keys"`
	// aggregated G1 public keys
	Apk1 [2]string `json:"apk1"`
	// aggregated G2 public keys
	Apk2 [4]string `json:"apk2"`
	// message to sign
	Message string `json:"message"`
	// aggregated signature
	Signature [2]string `json:"signature"`
}

type identity struct {
	addr common.Address
	pri  *bls.PriKey
	pub1 *bls.PubKey1
	pub2 *bls.PubKey2
}
type identities []*identity

// get all addresses of identities
func (ids identities) getAddresses() []common.Address {
	addresses := make([]common.Address, len(ids))
	for i := 0; i < len(ids); i++ {
		addresses[i] = ids[i].addr
	}
	return addresses
}

// get all public keys on G1 in string
func (ids identities) getPubKeys() [][2]string {
	// this is not the right idena address, just for test
	pubKeys := make([][2]string, len(ids))
	for i := 0; i < len(ids); i++ {
		pubKeys[i] = ids[i].pub1.ToHex()
	}
	return pubKeys
}

type idState struct {
	Address common.Address `json:"address"`
	PubKey  [2]string      `json:"pubKey"`
}

func (id *identity) toState() *idState {
	return &idState{
		Address: id.addr,
		PubKey:  id.pub1.ToHex(),
	}
}

type idenaCheckState struct {
	Valid      bool     `json:"valid"`
	Height     int      `json:"height"`
	Population int      `json:"population"`
	StateRoot  string   `json:"root"`
	FirstId    *idState `json:"firstId"`
	LastId     *idState `json:"lastId"`
	MiddleId   *idState `json:"middleId"`
}

type idenaInitState struct {
	Comment string `json:"comment"`
	Height  int    `json:"height"`
	// new identities' addresses
	Identities []common.Address `json:"identities"`
	// new identities' public keys (G1)
	PubKeys [][2]string `json:"pubKeys"`
	// check conditions
	Checks *idenaCheckState `json:"checks"`
}

type idenaUpdateState struct {
	Comment string `json:"comment"`
	Height  int    `json:"height"`
	// new identities' addresses
	NewIdentities []common.Address `json:"newIdentities"`
	// new identities' public keys (G1)
	NewPubKeys [][2]string `json:"newPubKeys"`
	// flags of remove identities
	RemoveFlags Bytes `json:"removeFlags"`
	RemoveCount int   `json:"removeCount"`
	// flags of signers
	SignFlags Bytes `json:"signFlags"`
	// aggregated signature
	Signature [2]string `json:"signature"`
	// aggregated public keys of signers
	Apk2 [4]string `json:"apk2"`
	// check conditions
	Checks *idenaCheckState `json:"checks"`
}

type idenaTestData struct {
	Init    *idenaInitState     `json:"init"`
	Updates []*idenaUpdateState `json:"updates"`
}
