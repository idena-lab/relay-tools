package contract

import (
	"github.com/idena-network/idena-go/common"
	"github.com/idena-network/idena-go/crypto"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestNewIdentity(t *testing.T) {
	ecdPri, err := crypto.HexToECDSA("2dedd85746f99b685cffe420b7d96c5062ae80ff25d48731d03ee8fc4ed1fae0")
	require.NoError(t, err)
	id := NewIdentity(ecdPri)
	require.Equal(t, id.addr, common.HexToAddress("0xd611254eE6b8b225bd685cFb8933882CCd447675"))
	require.Equal(t, id.blsPri.ToHex(), "0x1ae6558a584ecf9b566b263222d44e6c485ba0bc0e68798e331d68518c222bcc")
}
