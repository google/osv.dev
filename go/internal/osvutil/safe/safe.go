// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package safe provides simple utilities to spawn goroutines with panic recovery
// and propagate those panics back to the main thread as error values.
package safe

import (
	"context"
	"fmt"
	"runtime/debug"
)

// PanicError wraps a panic value and its stack trace.
type PanicError struct {
	Value any
	Stack []byte
}

func (p *PanicError) Error() string {
	return fmt.Sprintf("panic recovered: %v", p.Value)
}

// GoCancel spawns a goroutine. If it panics, it cancels the context with a PanicError.
func GoCancel(cancel context.CancelCauseFunc, f func()) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				cancel(&PanicError{
					Value: r,
					Stack: debug.Stack(),
				})
			}
		}()
		f()
	}()
}

// Func wraps any function with panic recovery, propagating it to a callback.
func Func(onPanic func(r any, stack []byte), f func()) func() {
	return func() {
		defer func() {
			if r := recover(); r != nil {
				onPanic(r, debug.Stack())
			}
		}()
		f()
	}
}

// ErrgroupFunc wraps a function returning an error with panic recovery.
// If the function panics, it recovers the panic and returns a PanicError as the error,
// allowing it to propagate through errgroup.Group tasks safely.
func ErrgroupFunc(f func() error) func() error {
	return func() (err error) {
		defer func() {
			if r := recover(); r != nil {
				err = &PanicError{
					Value: r,
					Stack: debug.Stack(),
				}
			}
		}()

		return f()
	}
}
