package keyring

import (
	"fmt"
	"math/big"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"

	ledger "github.com/cosmos/ledger-cosmos-go"

	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
)

func signWithLedger(device *ledger.LedgerCosmos, k Key, bzToSign []byte) ([]byte, error) {
	path, err := k.getBip44Path()
	if err != nil {
		return nil, fmt.Errorf("getBip44Path: %w", err)
	}
	signature, err := device.SignSECP256K1(path.DerivationPath(), bzToSign, 0)
	if err != nil {
		return nil, fmt.Errorf("SignSECP256K1: %w", err)
	}
	signature, err = convertDERtoBER(signature)
	if err != nil {
		return nil, fmt.Errorf("convertDERtoBER: %w", err)
	}
	return signature, nil
}

func getLedgerPubKey(device *ledger.LedgerCosmos, bip32Path []uint32) (cryptotypes.PubKey, error) {
	pubKey, err := device.GetPublicKeySECP256K1(bip32Path)
	if err != nil {
		return nil, err
	}
	// re-serialize in the 33-byte compressed format
	cmp, err := btcec.ParsePubKey(pubKey)
	if err != nil {
		return nil, fmt.Errorf("error parsing public key: %v", err)
	}

	compressedPublicKey := make([]byte, secp256k1.PubKeySize)
	copy(compressedPublicKey, cmp.SerializeCompressed())

	return &secp256k1.PubKey{Key: compressedPublicKey}, nil
}

func convertDERtoBER(signatureDER []byte) ([]byte, error) {
	sigDER, err := ecdsa.ParseDERSignature(signatureDER)
	if err != nil {
		return nil, err
	}

	sigStr := sigDER.Serialize()
	// The format of a DER encoded signature is as follows:
	// 0x30 <total length> 0x02 <length of R> <R> 0x02 <length of S> <S>
	r, s := new(big.Int), new(big.Int)
	r.SetBytes(sigStr[4 : 4+sigStr[3]])
	s.SetBytes(sigStr[4+sigStr[3]+2:])

	sModNScalar := new(btcec.ModNScalar)
	sModNScalar.SetByteSlice(s.Bytes())
	// based on https://github.com/tendermint/btcd/blob/ec996c5/btcec/signature.go#L33-L50
	if sModNScalar.IsOverHalfOrder() {
		s = new(big.Int).Sub(btcec.S256().N, s)
	}

	sigBytes := make([]byte, 64)
	// 0 pad the byte arrays from the left if they aren't big enough.
	copy(sigBytes[32-len(r.Bytes()):32], r.Bytes())
	copy(sigBytes[64-len(s.Bytes()):64], s.Bytes())

	return sigBytes, nil
}
