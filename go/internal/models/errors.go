package models

import "errors"

// ErrNotFound indicates that a requested entity was not found.
var ErrNotFound = errors.New("not found")
