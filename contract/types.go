package contract

import (
	"crypto/ecdsa"
	"github.com/idena-lab/bls-256-go"
	"github.com/idena-network/idena-go/common"
	"github.com/idena-network/idena-go/common/hexutil"
	"github.com/idena-network/idena-go/crypto"
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
	ecdPri *ecdsa.PrivateKey
	addr   common.Address
	blsPri *bls.PriKey
	pub1   *bls.PubKey1
	pub2   *bls.PubKey2
}

// ec2BlsSeed = keccak256("bls-256-for-eth-relay")
// 0x4a2da48d3c8236407cb0ef9daf35c9579b5789df96555ce0dc338475c32fd6ee
var ec2BlsSeed = []byte{74, 45, 164, 141, 60, 130, 54, 64, 124, 176, 239, 157, 175, 53, 201, 87, 155, 87, 137, 223, 150, 85, 92, 224, 220, 51, 132, 117, 195, 47, 214, 238}

func NewIdentity(ecdPri *ecdsa.PrivateKey) *identity {
	id := &identity{
		ecdPri: ecdPri,
	}
	id.addr = crypto.PubkeyToAddress(ecdPri.PublicKey)
	seed, _ := crypto.Sign(ec2BlsSeed, ecdPri)
	id.blsPri, _ = bls.GenerateFromSeed(seed[:])
	id.pub1 = id.blsPri.GetPub1()
	id.pub2 = id.blsPri.GetPub2()
	return id
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

// get all ecdsa private keys
func (ids identities) getEcdPriKeys() []Bytes {
	priKeys:= make([]Bytes, len(ids))
	for i := 0; i < len(ids); i++ {
		priKeys[i] = crypto.FromECDSA(ids[i].ecdPri)
	}
	return priKeys
}

// get all public keys on G1 in string
func (ids identities) getPub1s() [][2]string {
	pubKeys := make([][2]string, len(ids))
	for i := 0; i < len(ids); i++ {
		pubKeys[i] = ids[i].pub1.ToHex()
	}
	return pubKeys
}

type idState struct {
	Address common.Address `json:"address"`
	EcdPri  Bytes          `json:"ecdPri"`
	BlsPub1 [2]string      `json:"blsPub1"`
}

func (id *identity) toState() *idState {
	return &idState{
		Address: id.addr,
		EcdPri:  crypto.FromECDSA(id.ecdPri),
		BlsPub1: id.pub1.ToHex(),
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
	Comment string      `json:"comment"`
	Height  int         `json:"height"`
	Root    common.Hash `json:"root"`
	// new identities' addresses
	Identities []common.Address `json:"identities"`
	// ecdsa private keys
	EcdPriKeys []Bytes `json:"ecdPriKeys"`
	// new identities' public keys (G1)
	BlsPub1s [][2]string `json:"blsPub1s"`
	// check conditions
	Checks *idenaCheckState `json:"checks"`
}

type idenaUpdateState struct {
	Comment string `json:"comment"`
	Height  int    `json:"height"`
	// new identities' addresses
	NewIdentities []common.Address `json:"newIdentities"`
	// ecdsa private keys
	NewEcdPriKeys []Bytes `json:"newEcdPriKeys"`
	// new identities' public keys (G1)
	NewBlsPub1s [][2]string `json:"newBlsPub1s"`
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
