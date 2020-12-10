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
	"github.com/dgrijalva/jwt-go"
	"github.com/go-playground/validator/v10"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"mecm-apprulemgr/models"
	"net/http"
	"os"
	"reflect"
	"strconv"
	"strings"
)

var (
	jwtPublicKey = os.Getenv("JWT_PUBLIC_KEY")
)

const (
	// Log related constants
	MaxSize    int = 20
	MaxBackups int = 50
	MaxAge         = 30

	// Rest method
	Post   = "POST"
	Get    = "GET"
	Put    = "PUT"
	Delete = "DELETE"

	// config result
	Success = "SUCCESS"
	Failure = "FAILURE"

	// default retry limit and interval
	DefaultRetryLimit    int = 30
	DefaultRetryInterval int = 2

	// error code
	BadRequest          int = 400
	StatusUnauthorized  int = 401
	InternalServerError int = 500

	// error messages
	ClientIpaddressInvalid    = "client ip address is invalid"
	MarshalProgressModelError = "failed to marshal progress model"
	MarshalAppRuleModelError  = "failed to marshal app rule model"
	UnknownRestMethod         = "unknown rest method"
	FailedToWriteRes          = "failed to write response into context"

	// log messages
	AppRuleConfigSuccess = "app rule configured successfully"
	AppRuleConfigFailed  = "app rule configuration failed"
	AppRuleConfigTimeout = "app rule configuration timeout"

	// app related constants
	AppInstanceId string = ":appInstanceId"
	TenantId      string = ":tenantId"

	MepAddress        = "MEP_SERVER_ADDR"
	MepPort           = "MEP_SERVER_PORT"
	DefaultMepAddress = "edgegallery"
	DefaultMepPort    = "80"

	// rest related constants
	HttpsUrl            string = "https://"
	AccessToken         string = "access_token"
	AuthorizationFailed string = "Authorization failed"
	MecmTenantRole      string = "ROLE_MECM_TENANT"
	MecmGuestRole       string = "ROLE_MECM_GUEST"
	InvalidToken        string = "invalid token"
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

// Get retry interval
func GetRetryInterval() int {
	retryInterval := GetAppConfig("retryInterval")
	i, err := strconv.Atoi(retryInterval)
	if err != nil {
		i = DefaultRetryInterval
	}
	return i
}

// Get retry limit
func GetRetryLimit() int {
	retryLimit := GetAppConfig("retryLimit")
	i, err := strconv.Atoi(retryLimit)
	if err != nil {
		i = DefaultRetryLimit
	}
	return i
}

// Does https request
func DoRequest(req *http.Request) (*http.Response, error) {
	config, err := TLSConfig("SSL_ROOT_CERT")
	if err != nil {
		log.Error("unable to send request")
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
	url := HttpsUrl + GetMepAddr() + ":" + GetMepPort() + "/mepcfg/app_lcm/v1/applications/" +
		appInstanceId + "/appd_configuration"
	return url
}

// Creates task query URL
func CreateTaskQueryUrl(taskId string) string {
	url := HttpsUrl + GetMepAddr() + ":" + GetMepPort() + "/mepcfg/app_lcm/v1/tasks/" +
		taskId + "/appd_configuration"
	return url
}

// Validate access token
func ValidateAccessToken(accessToken string, allowedRoles []string) error {
	if accessToken == "" {
		return errors.New("require token")
	}

	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(accessToken, claims, func(_ *jwt.Token) (interface{}, error) {
		return jwtPublicKey, nil
	})

	if token != nil && !token.Valid {
		err := validateTokenClaims(claims, allowedRoles)
		if err != nil {
			return err
		}
	} else if er, ok := err.(*jwt.ValidationError); ok {
		if er.Errors&jwt.ValidationErrorMalformed != 0 {
			log.Info("Invalid token")
			return errors.New(InvalidToken)
		} else if er.Errors&(jwt.ValidationErrorExpired|jwt.ValidationErrorNotValidYet) != 0 {
			log.Infof("token expired or inactive")
			return errors.New("token expired or inactive")
		} else {
			log.Info("Couldn't handle this token: ", err)
			return errors.New(err.Error())
		}
	} else {
		log.Info("Couldn't handle this token: ", err)
		return errors.New(err.Error())
	}

	log.Info("Token validated successfully")
	return nil
}

// Validate token claims
func validateTokenClaims(claims jwt.MapClaims, allowedRoles []string) error {
	if claims["authorities"] == nil {
		log.Info("Invalid token A")
		return errors.New(InvalidToken)
	}

	err := ValidateRole(claims, allowedRoles)
	if err != nil {
		return err
	}

	if claims["userId"] == nil {
		log.Info("Invalid token UI")
		return errors.New(InvalidToken)
	}
	if claims["user_name"] == nil {
		log.Info("Invalid token UN")
		return errors.New(InvalidToken)
	}
	err = claims.Valid()
	if err != nil {
		log.Info("token expired")
		return errors.New(InvalidToken)
	}
	return nil
}

func ValidateRole(claims jwt.MapClaims, allowedRoles []string) error {
	roleName := "defaultRole"
	log.Info(roleName)

	for key, value := range claims {
		if key == "authorities" {
			authorities := value.([]interface{})
			arr := reflect.ValueOf(authorities)
			for i := 0; i < arr.Len(); i++ {
				if arr.Index(i).Interface() == MecmTenantRole {
					roleName = MecmTenantRole
					break
				} else if arr.Index(i).Interface() == MecmGuestRole {
					roleName = MecmGuestRole
					break
				}
			}
			if !isRoleAllowed(roleName, allowedRoles) {
				log.Info("Invalid token A")
				return errors.New(InvalidToken)
			}
		}
	}
	return nil
}

func isRoleAllowed(actual string, allowed []string) bool {
	for _, v := range allowed {
		if v == actual {
			return true
		}
	}
	return false
}

// Creates progress model
func CreateOperationProgressModel(appInstanceId string, configResult string,
	details string) *models.OperationProgressModel {
	return &models.OperationProgressModel{
		AppInstanceId: appInstanceId,
		ConfigResult:  configResult,
		Detailed:      details,
	}
}

// Clear byte array from memory
func ClearByteArray(data []byte) {
	for i := 0; i < len(data); i++ {
		data[i] = 0
	}
}
