package keyring

import (
	"fmt"

	"github.com/tbruyelle/keyring-compat/codec"

	ledger "github.com/cosmos/ledger-cosmos-go"

	"github.com/cosmos/cosmos-sdk/crypto/hd"
	cosmoskeyring "github.com/cosmos/cosmos-sdk/crypto/keyring"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
	"github.com/cosmos/cosmos-sdk/types/bech32"
)

type Key struct {
	name string
	// record is not nil if the key is proto-encoded
	record *cosmoskeyring.Record
	// info is not nil if the key is amino-encoded
	info cosmoskeyring.LegacyInfo
}

func (k Key) Name() string {
	return k.name
}

func (k Key) Bech32Address(prefix string) (string, error) {
	addr, err := k.PubKey()
	if err != nil {
		return "", err
	}
	return bech32.ConvertAndEncode(prefix, addr.Address())
}

func (k Key) PubKey() (cryptotypes.PubKey, error) {
	if k.IsAminoEncoded() {
		return k.info.GetPubKey(), nil
	}
	pk, ok := k.record.PubKey.GetCachedValue().(cryptotypes.PubKey)
	if !ok {
		return nil, fmt.Errorf("can't get pubkey from Record")
	}
	return pk, nil
}

func (k Key) IsAminoEncoded() bool {
	return k.info != nil
}

func (k Key) RecordToInfo() (cosmoskeyring.LegacyInfo, error) {
	return legacyInfoFromRecord(k.record)
}

func (k Key) Type() cosmoskeyring.KeyType {
	if k.IsAminoEncoded() {
		return k.info.GetType()
	}
	return k.record.GetType()
}

func (k Key) Sign(bz []byte) ([]byte, cryptotypes.PubKey, error) {
	switch k.Type() {
	case cosmoskeyring.TypeLocal:
		privKey, err := k.getPrivKey()
		if err != nil {
			return nil, nil, err
		}
		signature, err := privKey.Sign(bz)
		if err != nil {
			return nil, nil, err
		}
		return signature, privKey.PubKey(), nil

	case cosmoskeyring.TypeLedger:
		device, err := ledger.FindLedgerCosmosUserApp()
		if err != nil {
			return nil, nil, err
		}
		return signWithLedger(device, k, bz)
	}
	return nil, nil, fmt.Errorf("unhandled key type %q", k.Type())
}

func (k Key) getBip44Path() (*hd.BIP44Params, error) {
	if k.IsAminoEncoded() {
		return k.info.GetPath()
	}
	return k.record.GetLedger().GetPath(), nil
}

func (k Key) getPrivKey() (cryptotypes.PrivKey, error) {
	if k.Type() != cosmoskeyring.TypeLocal {
		return nil, fmt.Errorf("Access to priv key is only for local key type")
	}
	if k.IsAminoEncoded() {
		// Get priv key from amino encoded key
		var privKey cryptotypes.PrivKey
		err := codec.Amino.Unmarshal([]byte(k.info.(legacyLocalInfo).GetPrivKeyArmor()), &privKey)
		if err != nil {
			return nil, err
		}
		return privKey, nil
	}
	// Get priv key from proto encoded key
	return extractPrivKeyFromLocal(k.record.GetLocal())
}

func extractPrivKeyFromLocal(rl *cosmoskeyring.Record_Local) (cryptotypes.PrivKey, error) {
	if rl.PrivKey == nil {
		return nil, cosmoskeyring.ErrPrivKeyNotAvailable
	}

	priv, ok := rl.PrivKey.GetCachedValue().(cryptotypes.PrivKey)
	if !ok {
		return nil, cosmoskeyring.ErrCastAny
	}

	return priv, nil
}

// legacyInfoFromLegacyInfo turns a Record into a LegacyInfo.
func legacyInfoFromRecord(record *cosmoskeyring.Record) (cosmoskeyring.LegacyInfo, error) {
	switch record.GetType() {
	case cosmoskeyring.TypeLocal:
		pk, err := record.GetPubKey()
		if err != nil {
			return nil, err
		}
		privKey, err := extractPrivKeyFromLocal(record.GetLocal())
		if err != nil {
			return nil, err
		}
		privBz, err := codec.Amino.Marshal(privKey)
		if err != nil {
			return nil, err
		}
		return legacyLocalInfo{
			Name:         record.Name,
			PubKey:       pk,
			Algo:         hd.PubKeyType(pk.Type()),
			PrivKeyArmor: string(privBz),
		}, nil

	case cosmoskeyring.TypeLedger:
		pk, err := record.GetPubKey()
		if err != nil {
			return nil, err
		}
		return legacyLedgerInfo{
			Name:   record.Name,
			PubKey: pk,
			Algo:   hd.PubKeyType(pk.Type()),
			Path:   *record.GetLedger().Path,
		}, nil

	case cosmoskeyring.TypeMulti:
		panic("record type TypeMulti unhandled")

	case cosmoskeyring.TypeOffline:
		panic("record type TypeOffline unhandled")
	}
	panic(fmt.Sprintf("record type %s unhandled", record.GetType()))
}
