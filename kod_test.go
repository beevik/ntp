package ntp

import "testing"

func TestKodMap(t *testing.T) {
	golden := []struct {
		code uint32
		err  error
	}{
		{0x41435354, ErrorACST},
		{0x41555448, ErrorAUTH},
		{0x4155544f, ErrorAUTO},
		{0x42435354, ErrorBCST},
		{0x43525950, ErrorCRYP},
		{0x44454e59, ErrorDENY},
		{0x44524f50, ErrorDROP},
		{0x52535452, ErrorRSTR},
		{0x494e4954, ErrorINIT},
		{0x4d435354, ErrorMCST},
		{0x4e4b4559, ErrorNKEY},
		{0x52415445, ErrorRATE},
		{0x524d4f54, ErrorRMOT},
		{0x53544550, ErrorSTEP},
	}

	for _, g := range golden {
		if tg, existed := kodErrorMap[g.code]; !existed || tg != g.err {
			t.Errorf("%x expeting %s , got %s", g.code, g.err, tg)
		}
	}
}
