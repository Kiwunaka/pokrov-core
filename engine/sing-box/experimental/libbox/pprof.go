package libbox

import "errors"

type PProfServer struct{}

func NewPProfServer(port int) *PProfServer {
	return &PProfServer{}
}

func (s *PProfServer) Start() error {
	return errors.New("pprof listener is disabled in the client SDK")
}

func (s *PProfServer) Close() error {
	return nil
}
