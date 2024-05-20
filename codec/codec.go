package codec

import (
	"github.com/cosmos/cosmos-sdk/codec"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	cryptocodec "github.com/cosmos/cosmos-sdk/crypto/codec"
)

var (
	Proto *codec.ProtoCodec
	Amino *codec.LegacyAmino
)

func init() {
	registry := codectypes.NewInterfaceRegistry()
	cryptocodec.RegisterInterfaces(registry)
	Proto = codec.NewProtoCodec(registry)

	Amino = codec.NewLegacyAmino()
	cryptocodec.RegisterCrypto(Amino)
}
