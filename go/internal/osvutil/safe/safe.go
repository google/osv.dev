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

// Package safe provides simple utilities for panic recovery in goroutines and worker tasks,
// propagating recovered panics back to callbacks or as error values.
package safe

import (
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

// Func wraps a function f with panic recovery and returns a new function with the same signature.
//
// When the returned function is executed, it runs f. If f panics during execution, the panic
// is intercepted so it does not terminate the goroutine or crash the program. The recovered
// panic value r and the runtime stack trace are immediately passed to the onPanic callback.
//
// This is useful for safeguarding background tasks, worker callbacks, or goroutines managed
// by tools like sync.WaitGroup against unexpected crashes.
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
