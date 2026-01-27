package utils

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	"google.golang.org/grpc/credentials"
)

// LoadTLSCredentials loads TLS credentials for mTLS
func LoadTLSCredentials(serverCertFile, serverKeyFile, clientCACertFile string) (credentials.TransportCredentials, error) {
	// Load server certificate and key
	serverCert, err := tls.LoadX509KeyPair(serverCertFile, serverKeyFile)
	if err != nil {
		return nil, fmt.Errorf("could not load server key pair: %s", err)
	}

	// Load CA certificate
	certPool := x509.NewCertPool()
	caCert, err := os.ReadFile(clientCACertFile)
	if err != nil {
		return nil, fmt.Errorf("could not read ca certificate: %s", err)
	}

	if ok := certPool.AppendCertsFromPEM(caCert); !ok {
		return nil, fmt.Errorf("failed to append ca certificate")
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    certPool,
	}

	return credentials.NewTLS(config), nil
}

// LoadClientTLSCredentials loads client-side TLS credentials for mTLS
func LoadClientTLSCredentials(clientCertFile, clientKeyFile, serverCACertFile string) (credentials.TransportCredentials, error) {
	// Load client certificate and key
	clientCert, err := tls.LoadX509KeyPair(clientCertFile, clientKeyFile)
	if err != nil {
		return nil, fmt.Errorf("could not load client key pair: %s", err)
	}

	// Load CA certificate
	certPool := x509.NewCertPool()
	caCert, err := os.ReadFile(serverCACertFile)
	if err != nil {
		return nil, fmt.Errorf("could not read ca certificate: %s", err)
	}

	if ok := certPool.AppendCertsFromPEM(caCert); !ok {
		return nil, fmt.Errorf("failed to append ca certificate")
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      certPool,
	}

	return credentials.NewTLS(config), nil
}
