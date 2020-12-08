/*
 * Copyright 2020 Huawei Technologies Co., Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package util

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"github.com/astaxie/beego"
	"github.com/go-playground/validator/v10"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
)

const (
	// Log related constants
	MaxSize    int = 20
	MaxBackups int = 50
	MaxAge         = 30

	// input validations related constants
	BadRequest             int = 400
	ClientIpaddressInvalid     = "client ip address is invalid"

	AppInstanceId string = ":appInstanceId"

	MepAddress        = "MEP_ADDR"
	MepPort           = "MEP_PORT"
	DefaultMepAddress = "edgegallery"
	DefaultMepPort    = "8444"

	HttpsUrl string = "https://"
)

var cipherSuiteMap = map[string]uint16{
	"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256": tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384": tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
}

// Update tls configuration
func TLSConfig(crtName string) (*tls.Config, error) {
	certNameConfig := GetAppConfig(crtName)
	if len(certNameConfig) == 0 {
		log.Error(crtName + " configuration is not set")
		return nil, errors.New("cert name configuration is not set")
	}

	crt, err := ioutil.ReadFile(certNameConfig)
	if err != nil {
		log.Error("unable to read certificate")
		return nil, err
	}

	rootCAs := x509.NewCertPool()
	rootCAs.AppendCertsFromPEM(crt)

	sslCiphers := GetAppConfig("ssl_ciphers")
	if len(sslCiphers) == 0 {
		return nil, errors.New("TLS cipher configuration is not recommended or invalid")
	}
	cipherSuites := GetCipherSuites(sslCiphers)
	if cipherSuites == nil {
		return nil, errors.New("TLS cipher configuration is not recommended or invalid")
	}
	return &tls.Config{
		RootCAs:            rootCAs,
		MinVersion:         tls.VersionTLS12,
		CipherSuites:       cipherSuites,
		ServerName:         GetAppConfig("serverName"),
		InsecureSkipVerify: true,
	}, nil
}

// Get app configuration
func GetAppConfig(k string) string {
	return beego.AppConfig.String(k)
}

// To get cipher suites
func GetCipherSuites(sslCiphers string) []uint16 {
	cipherSuiteArr := make([]uint16, 0, 5)
	cipherSuiteNameList := strings.Split(sslCiphers, ",")
	for _, cipherName := range cipherSuiteNameList {
		cipherName = strings.TrimSpace(cipherName)
		if len(cipherName) == 0 {
			continue
		}
		mapValue, ok := cipherSuiteMap[cipherName]
		if !ok {
			log.Error("not recommended cipher suite")
			return nil
		}
		cipherSuiteArr = append(cipherSuiteArr, mapValue)
	}
	if len(cipherSuiteArr) > 0 {
		return cipherSuiteArr
	}
	return nil
}

// Validate IPv4 address
func ValidateIpv4Address(id string) error {
	if id == "" {
		return errors.New("require ip address")
	}
	if len(id) != 0 {
		validate := validator.New()
		return validate.Var(id, "required,ipv4")
	}
	return nil
}

// Get MEP address
func GetMepAddr() string {
	mepAddress := os.Getenv(MepAddress)
	if mepAddress == "" {
		mepAddress = DefaultMepAddress
	}
	return mepAddress
}

// Get MEP port
func GetMepPort() string {
	mepPort := os.Getenv(MepPort)
	if mepPort == "" {
		mepPort = DefaultMepPort
	}
	return mepPort
}

// Does https request
func DoRequest(req *http.Request) (*http.Response, error) {
	config, err := TLSConfig("DB_SSL_ROOT_CERT")
	if err != nil {
		log.Error("Unable to send request")
		return nil, err
	}

	tr := &http.Transport{
		TLSClientConfig: config,
	}
	client := &http.Client{Transport: tr}

	return client.Do(req)
}

// Creates appd Rule url
func CreateAppdRuleUrl(appInstanceId string) string {
	url := HttpsUrl + GetMepAddr() + ":" + GetMepPort() + "/app_lcm/v1/applications/" +
		appInstanceId + "/appd_configuration"
	return url
}

// Creates task query URL
func CreateTaskQueryUrl(taskId string) string {
	url := HttpsUrl + GetMepAddr() + ":" + GetMepPort() + "/app_lcm/v1/tasks/" +
		taskId + "/appd_configuration"
	return url
}
