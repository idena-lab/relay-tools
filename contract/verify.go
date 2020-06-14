package contract

import (
	"encoding/json"
	"fmt"
	"github.com/idena-lab/bls-256-go"
	"os"
)

// generate test cases for verify() in contract
func GenTestsForVerify(f *os.File) {
	items := []*verifyItem{
		{Keys: 1, Message: ""},
		{Keys: 1, Message: "idena go"},
		{Keys: 1, Message: "long message: 9999999999999999999999999999999999999999999999999999999999999999999999999999999999999999"},
		{Keys: 2, Message: "2 keys 1"},
		{Keys: 2, Message: "2 keys 2"},
		{Keys: 3, Message: "3 keys"},
		{Keys: 4, Message: "4 keys"},
		{Keys: 10, Message: "10 keys"},
		{Keys: 100, Message: "100 keys"},
		{Keys: 356, Message: "356 keys"},
		{Keys: 800, Message: "800 keys"},
		{Keys: 1024, Message: "1024 keys"},
		{Keys: 2048, Message: "2048 keys"},
		{Keys: 4000, Message: "4000 keys"},
		{Keys: 6000, Message: "4000 keys"},
		{Keys: 9000, Message: "9000 keys"},
		{Keys: 10000, Message: "10000 keys"},
	}
	priKeys := make([]*bls.PriKey, 0)
	pubKeys1 := make([]*bls.PubKey1, 0)
	pubKeys2 := make([]*bls.PubKey2, 0)
	for i, item := range items {
		fmt.Printf("generating %v: keys=%v, message=%v\n", i+1, item.Keys, item.Message)
		// prepare keys
		for i := len(priKeys); i < item.Keys; i++ {
			k, _ := bls.NewPriKey(nil)
			priKeys = append(priKeys, k)
			pubKeys1, pubKeys2 = append(pubKeys1, k.GetPub1()), append(pubKeys2, k.GetPub2())
		}
		sigs := make([]*bls.Signature, item.Keys)
		for i := 0; i < item.Keys; i++ {
			sigs[i] = priKeys[i].Sign([]byte(item.Message))
		}
		asig := bls.AggregateSignatures(sigs)
		item.Signature = asig.ToHex()
		apk1 := bls.AggregatePubKeys1(pubKeys1[:item.Keys])
		item.Apk1 = apk1.ToHex()
		apk2 := bls.AggregatePubKeys2(pubKeys2[:item.Keys])
		item.Apk2 = apk2.ToHex()
	}
	s, _ := json.MarshalIndent(items, "", "  ")
	_, _ = f.Write(s)
	fmt.Printf("\n> Data has written to %v\n", f.Name())
}
