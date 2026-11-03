// Package progress carries control-plane and relay progress independently of
// human-readable logging.
package progress

type Status string

const (
	Running Status = "running"
	OK      Status = "ok"
	Retry   Status = "retry"
	Info    Status = "info"
	Failed  Status = "error"
)

type Event struct {
	Stage    string
	Hop      string
	Network  string
	Status   Status
	Detail   string
	Err      error
	Terminal bool
}

type Observer func(Event)

func (observer Observer) Emit(event Event) {
	if observer != nil {
		observer(event)
	}
}
