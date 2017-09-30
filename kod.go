package ntp

import "errors"

/*

This file contains KOD (Kiss-o-Death) Error type.
See https://tools.ietf.org/html/rfc5905#section-7.4 for more detail

*/

var (
	// ErrorACST the association belongs to a unicast server
	ErrorACST = errors.New("the association belongs to a unicast server")
	// ErrorAUTH server authentication failed
	ErrorAUTH = errors.New("server authentication failed")
	// ErrorAUTO autokey sequence failed
	ErrorAUTO = errors.New("autokey sequence failed")
	// ErrorBCST the association belongs to a broadcast server
	ErrorBCST = errors.New("the association belongs to a broadcast server")
	// ErrorCRYP cryptographic authentication or identification failed
	ErrorCRYP = errors.New("cryptographic authentication or identification failed")
	// ErrorDENY access denied by remote server
	ErrorDENY = errors.New("access denied by remote server")
	// ErrorDROP lost peer in symmetric mode
	ErrorDROP = errors.New("lost peer in symmetric mode")
	// ErrorRSTR access denied due to local policy
	ErrorRSTR = errors.New("access denied due to local policy")
	// ErrorINIT the association has not yet synchronized for the first time
	ErrorINIT = errors.New("the association has not yet synchronized for the first time")
	// ErrorMCST the association belongs to a dynamically discovered server
	ErrorMCST = errors.New("the association belongs to a dynamically discovered server")
	// ErrorNKEY no key found
	ErrorNKEY = errors.New("no key found")
	// ErrorRATE rate exceeded
	ErrorRATE = errors.New("rate exceeded")
	// ErrorRMOT alteration of association from a remote host running ntpdc
	ErrorRMOT = errors.New("alteration of association from a remote host running ntpdc")
	// ErrorSTEP a step change in system time has occurred, but the association has not yet resynchronized
	ErrorSTEP = errors.New("a step change in system time has occurred, but the association has not yet resynchronized")

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
