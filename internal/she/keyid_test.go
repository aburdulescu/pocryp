package she

import (
	"testing"
)

func TestIsCompatible(t *testing.T) {
	t.Run("IdNotValid", func(t *testing.T) {
		if err := KeyID(255).IsCompatible(KEY_1); err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("OtherIdNotValid", func(t *testing.T) {
		if err := MASTER_ECU_KEY.IsCompatible(KeyID(255)); err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("SECRET_KEY", func(t *testing.T) {
		if err := SECRET_KEY.IsCompatible(KEY_1); err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("CompatibleWithThemselves", func(t *testing.T) {
		ids := []KeyID{
			MASTER_ECU_KEY,
			BOOT_MAC_KEY,
			BOOT_MAC,
		}

		t.Run("NOK", func(t *testing.T) {
			wrongOther := KEY_1
			for _, id := range ids {
				t.Run(id.String(), func(t *testing.T) {
					if err := id.IsCompatible(wrongOther); err == nil {
						t.Fatal("expected error")
					}
				})
			}
		})

		t.Run("OK", func(t *testing.T) {
			for _, id := range ids {
				t.Run(id.String(), func(t *testing.T) {
					if err := id.IsCompatible(id); err != nil {
						t.Fatal(err)
					}
				})
			}
		})

	})

	t.Run("KEY_n", func(t *testing.T) {
		ids := []KeyID{
			KEY_1,
			KEY_2,
			KEY_3,
			KEY_4,
			KEY_5,
			KEY_6,
			KEY_7,
			KEY_8,
			KEY_9,
			KEY_10,
		}

		t.Run("NOK", func(t *testing.T) {
			wrongs := []KeyID{
				SECRET_KEY,
				BOOT_MAC_KEY,
				BOOT_MAC,
				RAM_KEY,
			}
			for _, id := range ids {
				t.Run(id.String(), func(t *testing.T) {
					for _, wrong := range wrongs {
						t.Run(wrong.String(), func(t *testing.T) {
							if err := id.IsCompatible(wrong); err == nil {
								t.Fatal("expected error")
							}
						})
					}
				})
			}
		})

		t.Run("OK", func(t *testing.T) {
			for _, id := range ids {
				t.Run(id.String(), func(t *testing.T) {
					if err := id.IsCompatible(id); err != nil {
						t.Fatal(err)
					}
					if err := id.IsCompatible(MASTER_ECU_KEY); err != nil {
						t.Fatal(err)
					}
				})
			}
		})

	})

	t.Run("RAM_KEY", func(t *testing.T) {

		t.Run("NOK", func(t *testing.T) {
			wrongs := []KeyID{
				MASTER_ECU_KEY,
				BOOT_MAC_KEY,
				BOOT_MAC,
				RAM_KEY,
			}
			for _, wrong := range wrongs {
				t.Run(wrong.String(), func(t *testing.T) {
					if err := RAM_KEY.IsCompatible(wrong); err == nil {
						t.Fatal("expected error")
					}
				})
			}
		})

		t.Run("OK", func(t *testing.T) {
			ids := []KeyID{
				SECRET_KEY,
				KEY_1,
				KEY_2,
				KEY_3,
				KEY_4,
				KEY_5,
				KEY_6,
				KEY_7,
				KEY_8,
				KEY_9,
				KEY_10,
			}
			for _, id := range ids {
				t.Run(id.String(), func(t *testing.T) {
					if err := RAM_KEY.IsCompatible(id); err != nil {
						t.Fatal(err)
					}
				})
			}
		})

	})

}
