package httptools

type StatusError struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
	Err  error  `json:"err"`
}

func (e *StatusError) Error() string { return e.Msg }
func (e *StatusError) Unwrap() error { return e.Err }
