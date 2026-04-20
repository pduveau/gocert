package pkerr

import (
	"fmt"
	"reflect"
	"runtime"
	"strings"
)

type Kerror interface {
	Error() string
	Num() ErrorNumeric
	Equal(Kerror) bool
	internal() *BaseError
}

type BaseError struct {
	file   string
	line   int
	format string
	errNum ErrorNumeric
	data   []any
}

func (e *BaseError) Equal(g Kerror) bool {
	return reflect.DeepEqual(e.data, g.internal().data) && e.format == g.internal().format && e.errNum == g.internal().errNum
}

func (e *BaseError) internal() *BaseError {
	return e
}

func (e *BaseError) Error() string {
	f := fmt.Sprintf("%s:%d %s", e.file, e.line, e.format)
	return fmt.Sprintf(f, e.data...)
}

func (e *BaseError) Num() ErrorNumeric {
	return e.errNum
}

func NewBaseErrorData(num ErrorNumeric, format string, data ...any) BaseError {
	_, file, line, _ := runtime.Caller(2)
	file = "gocert" + strings.Split(file, "gocert")[1]
	return BaseError{
		file:   file,
		line:   line,
		data:   data,
		errNum: num,
		format: format,
	}
}

func NewBaseError(num ErrorNumeric, format string) BaseError {
	_, file, line, _ := runtime.Caller(2)
	file = "gocert" + strings.Split(file, "gocert")[1]
	return BaseError{
		file:   file,
		line:   line,
		format: format,
		errNum: num,
	}
}

type ErrNative struct{ BaseError }

func NewErrNative(err error) Kerror {
	if err == nil {
		return nil
	}
	_, file, line, _ := runtime.Caller(1)
	file = "gocert" + strings.Split(file, "gocert")[1]
	return &ErrNative{BaseError{
		file:   file,
		line:   line,
		data:   []any{},
		errNum: 0,
		format: err.Error(),
	}}
}

/*type Err struct{ BaseError }

func New() Pkerror {
	return &{BaseError: NewBaseError(0, "")}
}

/*type Err struct{ BaseError }

func New() Pkerror {
	return &{BaseError: NewBaseError(0, "")}
}

/*type Err struct{ BaseError }

func New() Pkerror {
	return &{BaseError: NewBaseError(0, "")}
}

/*type Err struct{ BaseError }

func New() Pkerror {
	return &{BaseError: NewBaseError(0, "")}
}

/*type Err struct{ BaseError }

func New() Pkerror {
	return &{BaseError: NewBaseError(0, "")}
}

*/
