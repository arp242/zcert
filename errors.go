package zcert

import (
	"strings"
	"sync"
)

// Copy of zgo.at/errors

// Group multiple errors.
type Group struct {
	// Maximum number of errors; calls to Append() won't do anything if the number of errors is larger than this.
	MaxSize int

	mu    *sync.Mutex
	errs  []error
	nerrs int
}

// NewGroup create a new Group instance. It will record a maximum of maxSize
// errors. Set to 0 for no limit.
func NewGroup(maxSize int) *Group {
	return &Group{MaxSize: maxSize, mu: new(sync.Mutex)}
}

func (g Group) Error() string {
	if len(g.errs) == 0 {
		return ""
	}

	var b strings.Builder
	for _, e := range g.errs {
		b.WriteString(e.Error())
		b.WriteByte('\n')
	}
	return b.String()
}

// Len returns the number of errors.
func (g Group) Len() int { return len(g.errs) }

// Append a new error to the list; this is thread-safe.
//
// It won't do anything if the error is nil, in which case it will return false.
// This makes appending errors in a loop slightly nicer:
//
//   for {
//       err := do()
//       if errors.Append(err) {
//           continue
//       }
//   }
func (g *Group) Append(err error) bool {
	if err == nil {
		return false
	}

	g.mu.Lock()
	defer g.mu.Unlock()
	g.nerrs++
	if g.MaxSize == 0 || len(g.errs) < g.MaxSize {
		g.errs = append(g.errs, err)
	}
	return true
}

// ErrorOrNil returns itself if there are errors, or nil otherwise.
//
// It avoids an if-check at the end:
//
//   return errs.ErrorOrNil()
func (g *Group) ErrorOrNil() error {
	if g.Len() == 0 {
		return nil
	}
	return g
}
