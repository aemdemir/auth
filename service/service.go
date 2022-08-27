package service

import (
	"fmt"
	"runtime/debug"

	"github.com/rs/zerolog"
)

// background executes fn in a goroutine.
func background(logger zerolog.Logger, fn func()) {
	go func() {
		defer func() {
			if err := recover(); err != nil {
				logger.Error().
					Err(fmt.Errorf("%s", err)).
					Str("trace", string(debug.Stack())).
					Msg("panic recovered from background goroutine")
			}
		}()
		fn()
	}()
}
