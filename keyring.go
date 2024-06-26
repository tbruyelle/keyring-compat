package keyring

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/99designs/keyring"
	"github.com/bgentry/speakeasy"
	"github.com/tbruyelle/keyring-compat/codec"

	cosmoskeyring "github.com/cosmos/cosmos-sdk/crypto/keyring"
)

type Keyring struct {
	dir string
	k   keyring.Keyring
}

type BackendType = keyring.BackendType

func New(backend BackendType, dir string, filePasswordFunc func(string) (string, error)) (Keyring, error) {
	if filePasswordFunc == nil {
		filePasswordFunc = func(_ string) (string, error) {
			return speakeasy.FAsk(os.Stderr, fmt.Sprintf("Enter password for keyring %q: ", dir))
		}
	}
	k, err := keyring.Open(keyring.Config{
		// TODO: test with other backend
		AllowedBackends:  []keyring.BackendType{backend},
		FileDir:          dir,
		FilePasswordFunc: filePasswordFunc,
	})
	if err != nil {
		return Keyring{}, err
	}
	return Keyring{dir: dir, k: k}, nil
}

func (k Keyring) Keys() ([]Key, error) {
	var keys []Key
	names, err := k.k.Keys()
	if err != nil {
		return nil, fmt.Errorf("keyring.Keys: %w", err)
	}
	for _, name := range names {
		if !strings.HasSuffix(name, ".info") {
			continue
		}
		key, err := k.Get(name)
		if err != nil {
			return nil, fmt.Errorf("key.Get: %w", err)
		}
		keys = append(keys, key)
	}
	return keys, nil
}

func (k Keyring) GetByAddress(addr string) (Key, error) {
	item, err := k.k.Get(hex.EncodeToString([]byte(addr)) + ".address")
	if err != nil {
		return Key{}, err
	}
	return k.Get(string(item.Data) + ".info")
}

func (k Keyring) Get(name string) (Key, error) {
	item, err := k.k.Get(name)
	if err != nil {
		return Key{}, err
	}

	// try proto decode
	var record cosmoskeyring.Record
	errProto := codec.Proto.Unmarshal(item.Data, &record)
	if errProto == nil {
		return Key{name: name, record: &record}, nil
	}
	// try amino decode
	var info cosmoskeyring.LegacyInfo
	errAmino := codec.Amino.UnmarshalLengthPrefixed(item.Data, &info)
	if errAmino == nil {
		// After unmarshalling into &info, if we notice that the info is a
		// multiInfo, then we unmarshal again, explicitly in a multiInfo this time.
		// Since multiInfo implements UnpackInterfacesMessage, this will correctly
		// unpack the underlying anys inside the multiInfo.
		//
		// This is a workaround, as go cannot check that an interface (Info)
		// implements another interface (UnpackInterfacesMessage).
		// NOTE(tb): scavanged from cosmos-sdk, maybe we should use the legacy types
		// instead of duplicate them here.
		_, ok := info.(legacyMultiInfo)
		if ok {
			var multi legacyMultiInfo
			err = codec.Amino.UnmarshalLengthPrefixed(item.Data, &multi)

			return Key{name: name, info: multi}, err
		}
		return Key{name: name, info: info}, nil
	}
	return Key{}, fmt.Errorf("cannot decode key %s: decodeProto=%v decodeAmino=%v", name, errProto, errAmino)
}

func (k Keyring) AddAmino(name string, info cosmoskeyring.LegacyInfo) error {
	bz, err := codec.Amino.MarshalLengthPrefixed(info)
	if err != nil {
		return err
	}
	return k.k.Set(keyring.Item{Key: name, Data: bz})
}

func (k Keyring) AddProto(name string, record *cosmoskeyring.Record) error {
	bz, err := codec.Proto.Marshal(record)
	if err != nil {
		return err
	}
	return k.k.Set(keyring.Item{Key: name, Data: bz})
}
