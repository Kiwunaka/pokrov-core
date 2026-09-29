package include

import (
	"github.com/sagernet/sing-box/adapter/certificate"
	originca "github.com/sagernet/sing-box/service/origin_ca"
)

func CertificateProviderRegistry() *certificate.Registry {
	registry := certificate.NewRegistry()
	registerACMECertificateProvider(registry)
	registerTailscaleCertificateProvider(registry)
	originca.RegisterCertificateProvider(registry)
	return registry
}
