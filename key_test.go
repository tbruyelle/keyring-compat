package keyring_test

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tbruyelle/keyring-compat"

	cosmoskeyring "github.com/cosmos/cosmos-sdk/crypto/keyring"
	"github.com/cosmos/cosmos-sdk/crypto/keys/ed25519"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

func TestKey(t *testing.T) {
	//-----------------------------------------
	// Setup
	require := require.New(t)
	assert := assert.New(t)
	kr, err := keyring.New(keyring.BackendType("file"), t.TempDir(),
		func(_ string) (string, error) { return "test", nil },
	)
	require.NoError(err)
	// Generate a local private key
	var (
		privkey = ed25519.GenPrivKeyFromSecret([]byte("secret"))
		pubkey  = privkey.PubKey()
	)
	record, err := cosmoskeyring.NewLocalRecord("local", privkey, pubkey)
	require.NoError(err)
	err = kr.AddProto("proto", record)
	require.NoError(err)
	protoKey, err := kr.Get("proto")
	require.NoError(err)
	info, err := protoKey.RecordToInfo()
	require.NoError(err)
	assert.Equal(info.GetAddress().String(), protoKey.MustBech32Address("cosmos"))
	protoKey2, err := kr.GetByAddress(info.GetAddress())
	require.NoError(err)
	assert.Equal(protoKey, protoKey2, "GetByAddress() != Get()")

	err = kr.AddAmino("amino", info)
	require.NoError(err)
	aminoKey, err := kr.Get("amino")
	require.NoError(err)
	pb, err := aminoKey.PubKey()
	require.NoError(err)
	aminoKey2, err := kr.GetByAddress(sdk.AccAddress(pb.Address().Bytes()))
	require.NoError(err)
	assert.Equal(aminoKey, aminoKey2, "GetByAddress() != Get()")

	//-----------------------------------------
	// IsAminoEncoded()
	assert.True(aminoKey.IsAminoEncoded())
	assert.False(protoKey.IsAminoEncoded())

	//-----------------------------------------
	// Type()
	assert.Equal("local", aminoKey.Type().String())
	assert.Equal("local", protoKey.Type().String())

	//-----------------------------------------
	// Bech32Address()
	expectedBech32 := "cosmos182t3l5ptfgrlcg926xfk60936f3mjms0djnj6g"
	for _, key := range []keyring.Key{protoKey, aminoKey} {
		addr, err := key.Bech32Address("cosmos")
		require.NoError(err)
		assert.Equal(expectedBech32, addr)
	}

	//-----------------------------------------
	// ProtoJSONPubKey()
	expectedProtoJSON := `{"@type":"/cosmos.crypto.ed25519.PubKey","key":"XQNqhYzon4REkXYuuJ4r+9UKSgoNpljksmKLJbEXrgk="}`
	for _, key := range []keyring.Key{protoKey, aminoKey} {
		bz, err := key.ProtoJSONPubKey()
		require.NoError(err)
		assert.Equal(expectedProtoJSON, string(bz))
	}

	//-----------------------------------------
	// Sign()
	expectedSignatureHex := "e1de06494e239e95a68b74b55460d1f1f376318bbd08af8f221f102ef8bc8f6d87922d8326defe6f4c71d577a17e105bf8ea7e4428cc410999fcc214f4068503"
	for _, key := range []keyring.Key{protoKey, aminoKey} {
		signature, err := key.Sign([]byte("hello world"))
		require.NoError(err)
		assert.Equal(expectedSignatureHex, hex.EncodeToString(signature))
	}
}
