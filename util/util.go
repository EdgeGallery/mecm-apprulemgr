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
	"github.com/astaxie/beego/context"
	"github.com/dgrijalva/jwt-go"
	"github.com/go-playground/validator/v10"
	uuid "github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
	"github.com/ulule/limiter/v3"
	"io/ioutil"
	"mecm-apprulemgr/models"
	"net/http"
	"os"
	"reflect"
	"regexp"
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
	StatusForbidden     int = 403

	// error messages
	ClientIpaddressInvalid            = "client ip address is invalid"
	MarshalProgressModelError         = "failed to marshal progress model"
	MarshalAppRuleModelError          = "failed to marshal app rule model"
	UnMarshalAppRuleModelError        = "failed to unmarshal app rule model"
	UnknownRestMethod                 = "unknown rest method"
	FailedToWriteRes                  = "failed to write response into context"
	AppInstanceIdInvalid              = "app instance id is invalid"
	TenantIdInvalid                   = "tenant id is invalid"
	RequestBodyTooLarge               = "request body too large"
	IllegalTenantId            string = "illegal TenantId"
	Forbidden                  string = "forbidden"

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
	AuthorizationFailed string = "authorization failed"
	MecmTenantRole      string = "ROLE_MECM_TENANT"
	MecmAdminRole       string = "ROLE_MECM_ADMIN"
	MecmGuestRole       string = "ROLE_MECM_GUEST"
	InvalidToken        string = "invalid token"
	AppRuleConfigPath   string = "/tenants/:tenantId/app_instances/:appInstanceId/appd_configuration"
	RequestBodyLength          = 4096
)

var cipherSuiteMap = map[string]uint16{
	"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256": tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384": tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
}

type RateLimiter struct {
	GeneralLimiter *limiter.Limiter
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
func ValidateAccessToken(accessToken string, allowedRoles []string, tenantId string) error {
	if accessToken == "" {
		return errors.New("require token")
	}

	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(accessToken, claims, func(_ *jwt.Token) (interface{}, error) {
		return jwtPublicKey, nil
	})

	if token != nil && !token.Valid {
		err := validateTokenClaims(claims, allowedRoles, tenantId)
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
func validateTokenClaims(claims jwt.MapClaims, allowedRoles []string, userRequestTenantId string) error {
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
	if userRequestTenantId != "" {
		err = ValidateUserIdFromRequest(claims, userRequestTenantId)
		if err != nil {
			return err
		}
	}
	return nil
}

func ValidateUserIdFromRequest(claims jwt.MapClaims, userIdFromRequest string) error {
	userIdFromToken := ""
	log.Info(userIdFromToken)

	for key, value := range claims {
		if key == "userId" {
			userId := value.(interface{})
			if userId != userIdFromRequest {
				log.Error("Illegal TenantId")
				return errors.New(IllegalTenantId)
			}
		}
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
				} else if arr.Index(i).Interface() == MecmAdminRole {
					roleName = MecmAdminRole
					break
				}
			}
			err := isValidUser(roleName, allowedRoles)
			if err != nil {
				log.Info("not authorised user")
				return err
			}
		}
	}
	return nil
}

func isValidUser(roleName string, allowedRoles []string) error {
	if !isRoleAllowed(roleName, allowedRoles) {
		log.Info("Invalid token Authorities")
		if roleName == MecmGuestRole {
			return errors.New(Forbidden)
		}
		return errors.New(InvalidToken)
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

// Validate UUID
func ValidateUUID(id string) error {
	if id == "" {
		return errors.New("require app instance id")
	}
	if len(id) != 0 {
		validate := validator.New()
		res := validate.Var(id, "required,uuid")
		if res != nil {
			return errors.New("UUID validate failed")
		}
	} else {
		return errors.New("UUID validate failed")
	}
	return nil
}

// validate by reg
func ValidateRegexp(strToCheck string, regexStr string, errMsg string) error {
	match, err := regexp.MatchString(regexStr, strToCheck)
	if err != nil {
		return err
	}
	if !match {
		return errors.New(errMsg)
	}
	return nil
}

func validateProtocol(fl validator.FieldLevel) bool {
	err := ValidateRegexp(fl.Field().String(), "^[a-zA-Z0-9]*$|^[a-zA-Z0-9][a-zA-Z0-9_\\-\\.]*[a-zA-Z0-9]$",
		"protocol validation failed")
	return err == nil
}

func validateName(fl validator.FieldLevel) bool {
	err := ValidateRegexp(fl.Field().String(), "^[a-zA-Z0-9]*$|^[a-zA-Z0-9][a-zA-Z0-9_\\-]*[a-zA-Z0-9]$",
		"name validation failed")
	return err == nil
}

// validate rest body
func ValidateRestBody(body interface{}) error {
	validate := validator.New()
	verrs := validate.RegisterValidation("validateName", validateName)
	if verrs != nil {
		return verrs
	}
	verrs = validate.RegisterValidation("validateProtocol", validateProtocol)
	if verrs != nil {
		return verrs
	}
	verrs = validate.Struct(body)
	if verrs != nil {
		for _, verr := range verrs.(validator.ValidationErrors) {
			log.Debugf("Namespace=%s, Field=%s, StructField=%s, Tag=%s, Kind =%s, Type=%s, Value=%s",
				verr.Namespace(), verr.Field(), verr.StructField(), verr.Tag(), verr.Kind(), verr.Type(),
				verr.Value())
		}
		return verrs
	}
	return nil
}

// Handle number of REST requests per second
func RateLimit(r *RateLimiter, ctx *context.Context) {
	var (
		limiterCtx limiter.Context
		err        error
		req        = ctx.Request
	)

	limiterCtx, err = r.GeneralLimiter.Get(req.Context(), "")
	if err != nil {
		ctx.Abort(http.StatusInternalServerError, err.Error())
		return
	}

	h := ctx.ResponseWriter.Header()
	h.Add("X-RateLimit-Limit", strconv.FormatInt(limiterCtx.Limit, 10))
	h.Add("X-RateLimit-Remaining", strconv.FormatInt(limiterCtx.Remaining, 10))
	h.Add("X-RateLimit-Reset", strconv.FormatInt(limiterCtx.Reset, 10))

	if limiterCtx.Reached {
		log.Infof("Too Many Requests on %s", ctx.Input.URL())
		ctx.Abort(http.StatusTooManyRequests, "429")
		return
	}
}

func GenerateUniqueId() string {
	return uuid.NewV4().String()
}