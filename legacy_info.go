package keyring

// imported from cosmos-sdk/crypto/keyring because of private types *LocalInfo

import (
	"fmt"

	"github.com/tbruyelle/keyring-compat/codec"

	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/crypto/hd"
	cosmoskeyring "github.com/cosmos/cosmos-sdk/crypto/keyring"
	"github.com/cosmos/cosmos-sdk/crypto/keys/multisig"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

var (
	_ cosmoskeyring.LegacyInfo = &legacyLocalInfo{}
	_ cosmoskeyring.LegacyInfo = &legacyLedgerInfo{}
	_ cosmoskeyring.LegacyInfo = &legacyOfflineInfo{}
	_ cosmoskeyring.LegacyInfo = &legacyMultiInfo{}
)

func init() {
	codec.Amino.RegisterInterface((*cosmoskeyring.LegacyInfo)(nil), nil)
	codec.Amino.RegisterConcrete(hd.BIP44Params{}, "crypto/keys/hd/BIP44Params", nil)
	codec.Amino.RegisterConcrete(legacyLocalInfo{}, "crypto/keys/localInfo", nil)
	codec.Amino.RegisterConcrete(legacyLedgerInfo{}, "crypto/keys/ledgerInfo", nil)
	codec.Amino.RegisterConcrete(legacyOfflineInfo{}, "crypto/keys/offlineInfo", nil)
	codec.Amino.RegisterConcrete(legacyMultiInfo{}, "crypto/keys/multiInfo", nil)
}

// legacyLocalInfo is the public information about a locally stored key
// Note: Algo must be last field in struct for backwards amino compatibility
type legacyLocalInfo struct {
	Name         string             `json:"name"`
	PubKey       cryptotypes.PubKey `json:"pubkey"`
	PrivKeyArmor string             `json:"privkey.armor"`
	Algo         hd.PubKeyType      `json:"algo"`
}

// GetType implements Info interface
func (i legacyLocalInfo) GetType() cosmoskeyring.KeyType {
	return cosmoskeyring.TypeLocal
}

// GetType implements Info interface
func (i legacyLocalInfo) GetName() string {
	return i.Name
}

// GetType implements Info interface
func (i legacyLocalInfo) GetPubKey() cryptotypes.PubKey {
	return i.PubKey
}

// GetType implements Info interface
func (i legacyLocalInfo) GetAddress() sdk.AccAddress {
	return i.PubKey.Address().Bytes()
}

// GetPrivKeyArmor
func (i legacyLocalInfo) GetPrivKeyArmor() string {
	return i.PrivKeyArmor
}

// GetType implements Info interface
func (i legacyLocalInfo) GetAlgo() hd.PubKeyType {
	return i.Algo
}

// GetType implements Info interface
func (i legacyLocalInfo) GetPath() (*hd.BIP44Params, error) {
	return nil, fmt.Errorf("BIP44 Paths are not available for this type")
}

// legacyLedgerInfo is the public information about a Ledger key
// Note: Algo must be last field in struct for backwards amino compatibility
type legacyLedgerInfo struct {
	Name   string             `json:"name"`
	PubKey cryptotypes.PubKey `json:"pubkey"`
	Path   hd.BIP44Params     `json:"path"`
	Algo   hd.PubKeyType      `json:"algo"`
}

// GetType implements Info interface
func (i legacyLedgerInfo) GetType() cosmoskeyring.KeyType {
	return cosmoskeyring.TypeLedger
}

// GetName implements Info interface
func (i legacyLedgerInfo) GetName() string {
	return i.Name
}

// GetPubKey implements Info interface
func (i legacyLedgerInfo) GetPubKey() cryptotypes.PubKey {
	return i.PubKey
}

// GetAddress implements Info interface
func (i legacyLedgerInfo) GetAddress() sdk.AccAddress {
	return i.PubKey.Address().Bytes()
}

// GetPath implements Info interface
func (i legacyLedgerInfo) GetAlgo() hd.PubKeyType {
	return i.Algo
}

// GetPath implements Info interface
func (i legacyLedgerInfo) GetPath() (*hd.BIP44Params, error) {
	tmp := i.Path
	return &tmp, nil
}

// legacyOfflineInfo is the public information about an offline key
// Note: Algo must be last field in struct for backwards amino compatibility
type legacyOfflineInfo struct {
	Name   string             `json:"name"`
	PubKey cryptotypes.PubKey `json:"pubkey"`
	Algo   hd.PubKeyType      `json:"algo"`
}

// GetType implements Info interface
func (i legacyOfflineInfo) GetType() cosmoskeyring.KeyType {
	return cosmoskeyring.TypeOffline
}

// GetName implements Info interface
func (i legacyOfflineInfo) GetName() string {
	return i.Name
}

// GetPubKey implements Info interface
func (i legacyOfflineInfo) GetPubKey() cryptotypes.PubKey {
	return i.PubKey
}

// GetAlgo returns the signing algorithm for the key
func (i legacyOfflineInfo) GetAlgo() hd.PubKeyType {
	return i.Algo
}

// GetAddress implements Info interface
func (i legacyOfflineInfo) GetAddress() sdk.AccAddress {
	return i.PubKey.Address().Bytes()
}

// GetPath implements Info interface
func (i legacyOfflineInfo) GetPath() (*hd.BIP44Params, error) {
	return nil, fmt.Errorf("BIP44 Paths are not available for this type")
}

// multiInfo is the public information about a multisig key
type legacyMultiInfo struct {
	Name      string               `json:"name"`
	PubKey    cryptotypes.PubKey   `json:"pubkey"`
	Threshold uint                 `json:"threshold"`
	PubKeys   []multisigPubKeyInfo `json:"pubkeys"`
}

type multisigPubKeyInfo struct {
	PubKey cryptotypes.PubKey `json:"pubkey"`
	Weight uint               `json:"weight"`
}

// GetType implements Info interface
func (i legacyMultiInfo) GetType() cosmoskeyring.KeyType {
	return cosmoskeyring.TypeMulti
}

// GetName implements Info interface
func (i legacyMultiInfo) GetName() string {
	return i.Name
}

// GetPubKey implements Info interface
func (i legacyMultiInfo) GetPubKey() cryptotypes.PubKey {
	return i.PubKey
}

// GetAddress implements Info interface
func (i legacyMultiInfo) GetAddress() sdk.AccAddress {
	return i.PubKey.Address().Bytes()
}

// GetPath implements Info interface
func (i legacyMultiInfo) GetAlgo() hd.PubKeyType {
	return hd.MultiType
}

// GetPath implements Info interface
func (i legacyMultiInfo) GetPath() (*hd.BIP44Params, error) {
	return nil, fmt.Errorf("BIP44 Paths are not available for this type")
}

// UnpackInterfaces implements UnpackInterfacesMessage.UnpackInterfaces
func (i legacyMultiInfo) UnpackInterfaces(unpacker codectypes.AnyUnpacker) error {
	multiPK := i.PubKey.(*multisig.LegacyAminoPubKey)

	return codectypes.UnpackInterfaces(multiPK, unpacker)
}
