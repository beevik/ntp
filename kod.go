package ntp

import "errors"

/*

This file contains KOD (Kiss-o-Death) Error type.
See https://tools.ietf.org/html/rfc5905#section-7.4 for more detail

*/

var (
	// ErrorACST the association belongs to a unicast server
	ErrorACST = errors.New("KOD ACST")

	// ErrorAUTH server authentication failed
	ErrorAUTH = errors.New("KOD AUTH")

	// ErrorAUTO autokey sequence failed
	ErrorAUTO = errors.New("KOD AUTO")

	// ErrorBCST the association belongs to a broadcast server
	ErrorBCST = errors.New("KOD BCST")

	// ErrorCRYP cryptographic authentication or identification failed
	ErrorCRYP = errors.New("KOD CRYP")

	// ErrorDENY access denied by remote server
	ErrorDENY = errors.New("KOD DENY")

	// ErrorDROP lost peer in symmetric mode
	ErrorDROP = errors.New("KOD DROP")

	// ErrorRSTR access denied due to local policy
	ErrorRSTR = errors.New("KOD RSTR")

	// ErrorINIT the association has not yet synchronized for the first time
	ErrorINIT = errors.New("KOD INIT")

	// ErrorMCST the association belongs to a dynamically discovered server
	ErrorMCST = errors.New("KOD MCST")

	// ErrorNKEY no key found
	ErrorNKEY = errors.New("KOD NKEY")

	// ErrorRATE rate exceeded
	ErrorRATE = errors.New("KOD RATE")

	// ErrorRMOT alteration of association from a remote host running ntpdc
	ErrorRMOT = errors.New("KOD RMOT")

	// ErrorSTEP a step change in system time has occurred, but the association has not yet resynchronized
	ErrorSTEP = errors.New("KOD STEP")

	kodErrorMap = map[uint32]error{
		stringToUint32("ACST"): ErrorACST,
		stringToUint32("AUTH"): ErrorAUTH,
		stringToUint32("AUTO"): ErrorAUTO,
		stringToUint32("BCST"): ErrorBCST,
		stringToUint32("CRYP"): ErrorCRYP,
		stringToUint32("DENY"): ErrorDENY,
		stringToUint32("DROP"): ErrorDROP,
		stringToUint32("RSTR"): ErrorRSTR,
		stringToUint32("INIT"): ErrorINIT,
		stringToUint32("MCST"): ErrorMCST,
		stringToUint32("NKEY"): ErrorNKEY,
		stringToUint32("RATE"): ErrorRATE,
		stringToUint32("RMOT"): ErrorRMOT,
		stringToUint32("STEP"): ErrorSTEP,
	}
)

func stringToUint32(s string) uint32 {
	return uint32(s[0])<<24 + uint32(s[1])<<16 + uint32(s[2])<<8 + uint32(s[3])
}
