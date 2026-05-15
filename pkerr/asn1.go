package pkerr

import (
	"fmt"
	"reflect"
)

type ErrAsn1TimeSerializationToOriginal struct{ BaseError }

func NewErrAsn1TimeSerialization(detail ...any) Kerror {
	return &ErrAsn1TimeSerializationToOriginal{BaseError: newBaseErrorData(NumErrAsn1TimeSerializationToOriginal, "time did not serialize back to the original value and may be invalid: given %q, but serialized as %q", detail...)}
}

type ErrAsn1Syntax struct{ BaseError }

func NewErrAsn1Syntax(msg ...any) Kerror {
	if len(msg) > 1 {
		format := fmt.Sprintf("syntax error: %s", msg[0])
		return &ErrAsn1Syntax{BaseError: newBaseErrorData(NumErrAsn1Syntax, format, msg[1:]...)}
	}
	return &ErrAsn1Syntax{BaseError: newBaseErrorData(NumErrAsn1Syntax, "syntax error: %s", msg...)}
}

type ErrAsn1Structural struct{ BaseError }

func NewErrAsn1Structural(msg ...any) Kerror {
	if len(msg) > 1 {
		format := fmt.Sprintf("syntax error: %s", msg[0])
		return &ErrAsn1Structural{BaseError: newBaseErrorData(NumErrAsn1Structural, format, msg[1:]...)}
	}
	return &ErrAsn1Structural{BaseError: newBaseErrorData(NumErrAsn1Structural, "syntax error: %s", msg...)}
}

type ErrAsn1Mashal struct{ BaseError }

func NewErrAsn1Marshal(msg ...any) Kerror {
	if len(msg) > 1 {
		format := fmt.Sprintf("syntax error: %s", msg[0])
		return &ErrAsn1Mashal{BaseError: newBaseErrorData(NumErrAsn1Mashal, format, msg[1:]...)}
	}
	return &ErrAsn1Mashal{BaseError: newBaseErrorData(NumErrAsn1Mashal, "marshal error: %s", msg...)}
}

// An invalidUnmarshalError describes an invalid argument passed to Unmarshal.
// (The argument to Unmarshal must be a non-nil pointer.)
type ErrInvalidUnmarshal struct{ BaseError }

func NewErrInvalidUnmarshal(typ reflect.Type) Kerror {
	if typ == nil {
		return &ErrInvalidUnmarshal{BaseError: newBaseError(NumErrInvalidUnmarshal, "Unmarshal recipient value is nil")}
	}
	if typ.Kind() != reflect.Pointer {
		return &ErrInvalidUnmarshal{BaseError: newBaseErrorData(NumErrInvalidUnmarshal, "Unmarshal recipient value is non-pointer %s", typ.String())}
	}
	return &ErrInvalidUnmarshal{BaseError: newBaseErrorData(NumErrInvalidUnmarshal, "Unmarshal recipient value is nil %s", typ.String())}
}
