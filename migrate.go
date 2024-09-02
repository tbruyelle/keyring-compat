package keyring

import (
	"fmt"
	"path/filepath"

	"github.com/99designs/keyring"
	"github.com/davecgh/go-spew/spew"
)

// MigrateProtoKeysToAmino turns all proto encoded keys from kr and migrate
// them to amino format, in a new keyring located in kr.dir/amino.
//
// This function is useful when by mistake you read a keyring that used to be
// amino-encoded with a binary that depends on cosmos-sdk >=v0.46, because it
// automatically migrates all amino keys into proto keys.
//
// Unlike cosmos-sdk, this migration is not destructive and is done in a
// separate keyring. Once migrated you can check that everything has been
// properly migrated by listing the keys from kr.dir/amino. Once you are OK
// with the result, you can simply copy the *.info files from kr.dir/amino
// into kr.dir, assuming that you used the same password for both keyring.
func (kr Keyring) MigrateProtoKeysToAmino() error {
	// new keyring for migrated keys
	aminoKeyringDir := filepath.Join(kr.dir, "amino")
	aminoKr, err := New(keyring.FileBackend, aminoKeyringDir, nil)
	if err != nil {
		return err
	}
	keys, err := kr.Keys()
	if err != nil {
		return err
	}
	for _, key := range keys {
		if key.IsAminoEncoded() {
			// this is a amino-encoded key  no migration just display
			fmt.Printf("%q (amino encoded)-> %s\n", key.name, spew.Sdump(key.info))
			continue
		}
		// this is a proto-encoded key let's migrate it back to amino
		fmt.Printf("%q (proto encoded)-> %s\n", key.name, spew.Sdump(key.record))
		info, err := key.RecordToInfo()
		if err != nil {
			return err
		}
		// Register new amino key_name.info -> amino encoded LegacyInfo
		if err := aminoKr.AddAmino(key.name, info); err != nil {
			return err
		}
		fmt.Printf("%q re-encoded to amino keyring %q\n", key.name, aminoKeyringDir)
	}
	return nil
}
