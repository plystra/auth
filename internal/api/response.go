package plane

import "encoding/json"

type Data[T any] struct {
	Data T `json:"data"`
}
type ErrorEnvelope struct {
	Error any `json:"error"`
}

func Marshal(v any) []byte { b, _ := json.Marshal(v); return b }
