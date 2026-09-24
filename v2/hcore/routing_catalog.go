package hcore

import "errors"

func RevokeRoutingCatalogService(serviceID string) (bool, error) {
	static.lock.Lock()
	defer static.lock.Unlock()
	if static.StartedService == nil {
		return false, errors.New("catalog_runtime_unavailable")
	}
	return static.StartedService.RevokeRoutingCatalogService(serviceID)
}

func RevokeRoutingCatalog() (bool, error) {
	static.lock.Lock()
	defer static.lock.Unlock()
	if static.StartedService == nil {
		return false, errors.New("catalog_runtime_unavailable")
	}
	return static.StartedService.RevokeRoutingCatalog()
}
