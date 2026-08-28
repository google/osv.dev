package models

import "errors"

// ErrNotFound indicates that a requested entity was not found.
var ErrNotFound = errors.New("not found")

// ErrInvalidArgument indicates that an argument provided to a function or method is invalid.
var ErrInvalidArgument = errors.New("invalid argument")
