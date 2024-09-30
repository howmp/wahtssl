package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"sync/atomic"
	"time"
)

type contextKey string

const isOpenSSLKey contextKey = "isOpenSSL"

func loadCert() tls.Certificate {
	cert, err := tls.LoadX509KeyPair("./certs/whatssl.guage.cool.crt", "./certs/whatssl.guage.cool.key")
	if err != nil {
		panic(err)
	}
	return cert
}
func main() {
	addr := "0.0.0.0:8443"
	// cert := loadCert()
	cert := loadCert()
	l, err := newTlsListener(addr, cert)
	if err != nil {
		panic(err)
	}
	httpServer := http.Server{
		Addr: addr,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			isOpenSSL, ok := r.Context().Value(isOpenSSLKey).(bool)
			if ok && isOpenSSL {
				fmt.Fprintf(w, "you are using OpenSSL\n")
			} else {
				fmt.Fprintf(w, "you are't using OpenSSL\n")
			}
		}),
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			isOpenSSL := false
			if tlsConn, ok := c.(*tls.Conn); ok {
				if fConn, ok := tlsConn.NetConn().(*filterConn); ok {
					isOpenSSL = fConn.isOpenSSL
				}
			}

			return context.WithValue(ctx, isOpenSSLKey, isOpenSSL)
		},
	}
	log.Println("listening on", addr)
	panic(httpServer.Serve(l))
}

type filterListener struct {
	net.Listener
}

func (l *filterListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &filterConn{Conn: conn, buf: &bytes.Buffer{}, done: &atomic.Bool{}}, nil
}

type filterConn struct {
	net.Conn
	buf       *bytes.Buffer
	done      *atomic.Bool
	isOpenSSL bool
}

func (c *filterConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if !c.done.Load() {
		c.buf.Write(b[:n])
	}
	return n, err
}

type tlsListener struct {
	net.Listener
}

func newTlsListener(addr string, cert tls.Certificate) (net.Listener, error) {
	tcpL, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	filterL := &filterListener{tcpL}
	config := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
		CipherSuites: []uint16{ // 选择aead模式的套件
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		},
	}
	return &tlsListener{tls.NewListener(filterL, config)}, nil
}

type errorConn struct {
	net.Conn
	err error
}

func (c *errorConn) Read(b []byte) (int, error) {
	return 0, c.err
}

func (c *errorConn) Write(b []byte) (int, error) {
	return 0, c.err
}

func (l *tlsListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	tlsConn := conn.(*tls.Conn)
	if err := tlsConn.Handshake(); err != nil {
		return &errorConn{conn, err}, nil
	}
	filterConn := tlsConn.NetConn().(*filterConn)
	filterConn.done.Store(true)
	record, err := parseFinishedRecord(filterConn.buf)
	if err == nil {
		// OpenSSL的sequence number不是从0开始
		// 但rfc5246要求sequence number从0开始
		// https://www.rfc-editor.org/rfc/rfc5246#page-19
		filterConn.isOpenSSL = !bytes.Equal(record.recordData[:8], []byte{0, 0, 0, 0, 0, 0, 0, 0})
	}
	return conn, nil

}

func newCert(name string) tls.Certificate {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		Subject:               pkix.Name{CommonName: name},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		panic(err)
	}
	certOut := &bytes.Buffer{}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyOut := &bytes.Buffer{}
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	cert, err := tls.X509KeyPair(certOut.Bytes(), keyOut.Bytes())
	if err != nil {
		panic(err)
	}
	return cert
}

const recordHeaderLen = 5

const (
	recordTypeChangeCipherSpec = 20
	recordTypeAlert            = 21
	recordTypeHandshake        = 22
	recordTypeApplicationData  = 23
)

const (
	typeHelloRequest        uint8 = 0
	typeClientHello         uint8 = 1
	typeServerHello         uint8 = 2
	typeNewSessionTicket    uint8 = 4
	typeEndOfEarlyData      uint8 = 5
	typeEncryptedExtensions uint8 = 8
	typeCertificate         uint8 = 11
	typeServerKeyExchange   uint8 = 12
	typeCertificateRequest  uint8 = 13
	typeServerHelloDone     uint8 = 14
	typeCertificateVerify   uint8 = 15
	typeClientKeyExchange   uint8 = 16
	typeFinished            uint8 = 20
	typeCertificateStatus   uint8 = 22
	typeKeyUpdate           uint8 = 24
)

type recordOrders []struct {
	recordType    byte
	handshakeType byte
	optional      bool
}

type tlsRecord struct {
	recordType uint8
	version    uint16
	recordData []byte
}

func readTlsRecord(reader io.Reader) (*tlsRecord, error) {
	hdr := make([]byte, recordHeaderLen)
	if _, err := io.ReadFull(reader, hdr); err != nil {
		return nil, err
	}
	recordType := hdr[0]
	version := uint16(hdr[1])<<8 | uint16(hdr[2])
	recordLen := int(hdr[3])<<8 | int(hdr[4])

	recordData := make([]byte, recordLen)
	if _, err := io.ReadFull(reader, recordData); err != nil {
		return nil, err
	}
	return &tlsRecord{
		recordType: recordType,
		version:    version,
		recordData: recordData,
	}, nil
}
func parseFinishedRecord(reader io.Reader) (*tlsRecord, error) {
	var orders = recordOrders{
		{
			recordType:    recordTypeHandshake,
			handshakeType: typeClientHello,
		},
		{
			recordType:    recordTypeHandshake,
			handshakeType: typeCertificate,
			optional:      true,
		},
		{
			recordType:    recordTypeHandshake,
			handshakeType: typeClientKeyExchange,
		},
		{
			recordType:    recordTypeHandshake,
			handshakeType: typeCertificateVerify,
			optional:      true,
		},
		{
			recordType: recordTypeChangeCipherSpec,
		},
		{
			recordType: recordTypeHandshake, // Encrypted Handshake Message(Finished)
		},
	}
	orderPos := 0
	for {
		record, err := readTlsRecord(reader)
		if err != nil {
			return nil, err
		}
		for pos := orderPos; pos < len(orders); pos++ {
			o := orders[pos]
			if o.handshakeType != 0 {
				// 需要判断握手类型
				if len(record.recordData) != 0 &&
					record.recordData[0] == o.handshakeType {
					orderPos = pos + 1
					break
				}
			} else {
				orderPos = pos + 1
				break
			}

			if o.optional {
				orderPos = pos + 1
				continue
			} else {
				return nil, fmt.Errorf(
					"invalid record, want %+v, got %d %x,",
					o, record.recordType, record.recordData,
				)
			}
		}
		if orderPos == len(orders) {
			return record, nil
		}
	}

}
