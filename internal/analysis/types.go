package analysis

type Symbol struct {
	Name    string `json:"name"`
	Address uint64 `json:"address"`
	Kind    string `json:"kind"`
	Module  string `json:"module,omitempty"`
}

type Annotation struct {
	Address uint64 `json:"address"`
	Text    string `json:"text"`
}

type StringHit struct {
	Address  uint64 `json:"address"`
	Encoding string `json:"encoding"`
	Value    string `json:"value"`
}

type XRef struct {
	From uint64 `json:"from"`
	To   uint64 `json:"to"`
	Kind string `json:"kind"`
}
