package she

import (
	"fmt"
)

//go:generate stringer -type=KeyID
type KeyID uint8

const (
	SECRET_KEY KeyID = iota
	MASTER_ECU_KEY
	BOOT_MAC_KEY
	BOOT_MAC
	KEY_1
	KEY_2
	KEY_3
	KEY_4
	KEY_5
	KEY_6
	KEY_7
	KEY_8
	KEY_9
	KEY_10
	RAM_KEY
)

func (id KeyID) IsValid() bool {
	return id < KeyID(len(_KeyID_index)-1)
}

func (id KeyID) IsCompatible(other KeyID) error {
	if !id.IsValid() {
		return fmt.Errorf("%s is not valid", id)
	}
	if !other.IsValid() {
		return fmt.Errorf("%s is not valid", other)
	}

	switch id {
	case
		MASTER_ECU_KEY,
		BOOT_MAC_KEY,
		BOOT_MAC:

		if other != id {
			return fmt.Errorf("%s can be updated only with itself", id)
		}

	case
		KEY_1,
		KEY_2,
		KEY_3,
		KEY_4,
		KEY_5,
		KEY_6,
		KEY_7,
		KEY_8,
		KEY_9,
		KEY_10:

		if other != id && other != MASTER_ECU_KEY {
			return fmt.Errorf("%s can be updated only with itself or %s", id, MASTER_ECU_KEY)
		}

	case RAM_KEY:

		if other != SECRET_KEY &&
			other != KEY_1 &&
			other != KEY_2 &&
			other != KEY_3 &&
			other != KEY_4 &&
			other != KEY_5 &&
			other != KEY_6 &&
			other != KEY_7 &&
			other != KEY_8 &&
			other != KEY_9 &&
			other != KEY_10 {
			return fmt.Errorf("%s can be updated only with %s or one of KEY_n", id, SECRET_KEY)
		}

	case SECRET_KEY:
		return fmt.Errorf("%s(%d) cannot be used", id, id)

	}

	return nil
}
