package hcore

import "errors"

// ResetNetwork clears existing network sessions and DNS state through the
// running router. The runtime, its configuration and inbounds remain in place.
func ResetNetwork() error {
	return static.resetNetwork()
}

func (h *PokrovInstance) resetNetwork() error {
	h.lock.Lock()
	defer h.lock.Unlock()
	box := h.Box()
	if box == nil {
		return errors.New("selector runtime unavailable")
	}
	box.Router().ResetNetwork()
	return nil
}
