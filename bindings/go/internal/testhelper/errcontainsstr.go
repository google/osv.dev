package testhelper

import (
	"fmt"
	"strings"
)

// ErrContainsStr is an error that matches other errors that contains
// `str` in their error string.
//
//nolint:errname
type ErrContainsStr struct {
	Str string
}

// Error returns the error string
func (e ErrContainsStr) Error() string { return fmt.Sprintf("error contains: '%s'", e.Str) }

// Is checks whether the input error contains the string in ErrContainsStr
func (e ErrContainsStr) Is(err error) bool {
	return strings.Contains(err.Error(), e.Str)
}
