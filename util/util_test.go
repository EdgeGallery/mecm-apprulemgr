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
	"encoding/json"
	"github.com/astaxie/beego"
	"github.com/dgrijalva/jwt-go"
	"github.com/stretchr/testify/assert"
	"mecm-apprulemgr/models"
	"net/http"
	"os"
	"testing"
	"time"
)

const (
	userId   = "e921ce54-82c8-4532-b5c6-8516cf75f7a6"
	tenantId = userId
)

func createToken(userid string, role string, isRole bool, isUserId bool) string {
	//Creating Access Token
	atClaims := jwt.MapClaims{}
	roleName := make([]string, 3)
	if isRole == true {
		roleName[0] = role
		roleName[1] = "ROLE_APPSTORE_TENANT"
		roleName[2] = "ROLE_DEVELOPER_TENANT"
	} else {
		roleName = nil
	}
	atClaims["authorities"] = roleName
	if isUserId == true {
		atClaims["user_name"] = "lcmcontroller"
	} else {
		atClaims["user_name"] = nil
	}
	atClaims["authorized"] = true
	if userid != "" {
		atClaims["userId"] = userid
	} else {
		atClaims["userId"] = nil
	}
	atClaims["exp"] = time.Now().Add(time.Minute * 60).Unix()
	at := jwt.NewWithClaims(jwt.SigningMethodHS256, atClaims)
	token, _ := at.SignedString([]byte("jdnfksdmfksd"))
	return token
}


func TestValidateAccessTokenRole(t *testing.T) {
	accessToken := createToken("1", "ROLE_MECM_GUEST", false, true)
	err := ValidateAccessToken(accessToken, []string{MecmGuestRole, MecmAdminRole}, tenantId)
	assert.Equal(t, "invalid token", err.Error(), "TestValidateAccessTokenSuccess execution result")
}

func TestValidateAccessTokenGuest(t *testing.T) {
	accessToken := createToken(tenantId, "ROLE_MECM_GUEST", true, true)
	err := ValidateAccessToken(accessToken, []string{MecmGuestRole, MecmAdminRole}, tenantId)
	assert.Nil(t, err, "TestValidateAccessTokenSuccess execution result")
}

func TestValidateAccessTokenInvalid(t *testing.T) {
	accessToken := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"
	err := ValidateAccessToken(accessToken, []string{MecmTenantRole}, "7f9cac8d-7c54-23e7-99c6-27e4d944d5de")
	assert.Error(t, err, "TestValidateAccessTokenInvalid execution result")
}

func TestValidateAccessTokenInvalid1(t *testing.T) {
	accessToken := "eyJ1c2VyX25hbWUiOiI3MjY5NjM4ZS01NjM3LTRiOGMtODE3OC1iNTExMmJhN2I2OWIiLCJzY29wZSI6WyJhbGwiXSwiZ" +
		"XhwIjoxNTk5Mjc5NDA3LCJzc29TZXNzaW9uSWQiOiI1QkYwNjM2QzlBMkEzMUI2NEEwMEFCRTk1OTVEN0E0NyIsInVzZXJOYW1lIjoid" +
		"2Vuc29uIiwidXNlcklkIjoiNzI2OTYzOGUtNTYzNy00YjhjLTgxNzgtYjUxMTJiYTdiNjliIiwiYXV0aG9yaXRpZXMiOlsiUk9MRV9BU" +
		"FBTVE9SRV9URU5BTlQiLCJST0xFX0RFVkVMT1BFUl9URU5BTlQiLCJST0xFX01FQ01fVEVOQU5UIl0sImp0aSI6IjQ5ZTBhMGMwLTIxZ" +
		"mItNDAwZC04M2MyLTI3NzIwNWQ1ZTY3MCIsImNsaWVudF9pZCI6Im1lY20tZmUiLCJlbmFibGVTbXMiOiJ0cnVlIn0."
	err := ValidateAccessToken(accessToken, []string{MecmTenantRole}, "7f9cac8d-7c54-23e7-99c6-27e4d944d5de")
	assert.Error(t, err, "TestValidateAccessTokenInvalid1 execution result")
}

func TestValidateIpv4AddressSuccess(t *testing.T) {
	err := ValidateIpv4Address("1.2.3.4")
	assert.NoError(t, err, "TestValidateIpv4AddressSuccess execution result")
}

func TestValidateIpv4AddressFailure(t *testing.T) {
	ip := ""
	err := ValidateIpv4Address(ip)
	assert.Error(t, err, "TestValidateIpv4AddressFailure execution result")
}

func TestValidateUUIDSuccess(t *testing.T) {
	uId := "6e5c8bf5-3922-4020-87d3-ee00163ca40d"
	err := ValidateUUID(uId)
	assert.NoError(t, err, "TestValidateUUIDSuccess execution result")
}

func TestValidateUUIDInvalid(t *testing.T) {
	uId := "sfAdsHuplrmDk44643s"
	err := ValidateUUID(uId)
	assert.Error(t, err, "TestValidateUUIDInvalid execution result")
}

func TestValidateUUIDFailure(t *testing.T) {
	uId := ""
	err := ValidateUUID(uId)
	assert.Error(t, err, "TestValidateUUIDFailure execution result")
}


func TestValidateAccessTokenSuccess(t *testing.T) {
	accessToken := createToken(userId, "ROLE_MECM_TENANT", true, true)
	err := ValidateAccessToken(accessToken, []string{MecmTenantRole}, tenantId)
	assert.Nil(t, err, "TestValidateAccessTokenSuccess execution result")
}

func TestValidateAccessTokenFailure(t *testing.T) {
	accessToken := ""
	err := ValidateAccessToken(accessToken, []string{MecmTenantRole}, tenantId)
	assert.Nil(t, err, "TestValidateAccessTokenFailure execution result")
}

func TestValidateAccessTokenFailure1(t *testing.T) {
	accessToken := createToken("1", "ROLE_MECM_TENANT", true, true)
	err := ValidateAccessToken(accessToken, []string{MecmTenantRole}, tenantId)
	assert.Equal(t, "illegal TenantId", err.Error(), "TestValidateAccessTokenFailure1 execution result")
}

func TestValidateAccessTokenFailure2(t *testing.T) {
	accessToken := createToken("1", "ROLE_MECM_TENANT", false, true)
	err := ValidateAccessToken(accessToken, []string{MecmTenantRole}, tenantId)
	assert.Equal(t, "invalid token", err.Error(), "TestValidateAccessTokenFailure2 execution result")
}

func TestValidateAccessTokenFailure3(t *testing.T) {
	accessToken := createToken("", "ROLE_MECM_TENANT", true, true)
	err := ValidateAccessToken(accessToken, []string{MecmTenantRole}, tenantId)
	assert.Equal(t, "invalid token", err.Error(), "TestValidateAccessTokenFailure3 execution result")
}

func TestValidateAccessTokenFailure4(t *testing.T) {
	accessToken := createToken(userId, "ROLE_MECM_TENANT", true, false)
	err := ValidateAccessToken(accessToken, []string{MecmTenantRole}, tenantId)
	assert.Equal(t, "invalid token", err.Error(), "TestValidateAccessTokenFailure4 execution result")
}

func TestValidateAccessTokenFailure5(t *testing.T) {
	accessToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdXRob3JpdGllcyI6WyJST0xFX01FQ01fQURNSU4iLCJST0xFX01FQ01fVEVOQU5UIiwiUk9MRV9BUFBTVE9SRV9URU5BTlQiLCJST0xFX0RFVkVMT1BFUl9URU5BTlQiXSwiYXV0aG9yaXplZCI6dHJ1ZSwiZXhwIjoxNjIzODU5MDg3LCJ1c2VySWQiOiJjOWZhNjA2OS0yODQ1LTQ2MmQtOGE2ZS1iOGE1MDFhNjNhZTIiLCJ1c2VyX25hbWUiOiJsY21jb250cm9sbGVyIn0.uZOnmni-wBKNH7XGr4u0nBtKLr_gYkvoP0zp3z0fWag"
	err := ValidateAccessToken(accessToken, []string{MecmTenantRole}, tenantId)
	assert.Equal(t, "invalid token", err.Error(), "TestValidateAccessTokenFailure5 execution result")
}


func TestValidateAccessTokenFailure6(t *testing.T) {
	accessToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdXRob3JpdGllcyI6WyJST0xFX01FQ01fQURNSU4iLCJST0xFX01FQ01fVEVOQU5UIiwiUk9MRV9BUFBTVE9SRV9URU5BTlQiLCJST0xFX0RFVkVMT1BFUl9URU5BTlQiXSwiYXV0aG9yaXplZCI6dHJ1ZSwiZXhwIjoxNjIzODU5MDg3LCJ1c2VySWQiOiJjOWZhNjA2OS0yODQ1LTQ2MmQtOGE2ZS1iOGE1MDFhNjNhZTIiLCJ1c2VyX25hbWUiOiJsY21jb250cm9sbGVyIn0.uZOnmni-wBKNH7XGr4u0nBtKLr_gYkvoP0zp3z0fWag"
	err := ValidateAccessToken(accessToken, []string{MecmAdminRole}, tenantId)
	assert.Equal(t, "invalid token", err.Error(), "TestValidateAccessTokenFailure6 execution result")
}

func TestTLSConfig(t *testing.T) {
	crtName := "crtName"
	_, err := TLSConfig(crtName)
	assert.Error(t, err, "TestTLSConfig execution result")
}

func TestGetCipherSuites(t *testing.T) {
	sslCiphers := "Dgashsdjh35xgkdgfsdhg"
	err := GetCipherSuites(sslCiphers)
	assert.Nil(t, err, "")
}

func TestGetAppConfig(_ *testing.T) {
	appConfig := "appConfig"
	GetAppConfig(appConfig)
}

func TestValidateRestBody(t *testing.T) {
	const (
		invalidFilterType = "{\"appTrafficRule\": [{\"trafficRuleId\":\"TrafficRule0\",\"filterType\": \"LOW\"," +
			"\"priority\": 1,\"trafficFilter\": [{\"srcAddress\": [\"192.168.1.1/28\"    ], \"dstAddress\":" +
			" [\"192.168.1.1/28\"],\"srcPort\": [\"8080\"],\"dstPort\": [\"8080\"], \"protocol\": [\"TCP\"],\"qCI\":" +
			" 1,\"dSCP\": 0,\"tC\": 1}],\"action\":\"DROP\",     \"state\": \"ACTIVE\"}],\"appDNSRule\": " +
			"[{\"dnsRuleId\": \"dnsRule4\",\"domainName\": \"www.example.com\",\"ipAddressType\":" +
			" \"IP_V4\",\"ipAddress\": \"192.0.0.0\", \"ttl\": 30,\"state\": \"ACTIVE\"}],\"appSupportMp1\": " +
			"true,\"appName\": \"abcd\"}"
		invalidPriority = "{\"appTrafficRule\": [{\"trafficRuleId\":\"TrafficRule1\",\"filterType\": \"FLOW\"," +
			"\"priority\": 0,\"trafficFilter\": [{\"srcAddress\": [\"192.168.1.1/28\"    ], \"dstAddress\":" +
			" [\"192.168.1.1/28\"],\"srcPort\": [\"8081\"],\"dstPort\": [\"8080\"], \"protocol\": [\"TCP\"],\"qCI\":" +
			" 1,\"dSCP\": 1,\"tC\": 1}],\"action\":\"DROP\",     \"state\": \"ACTIVE\"}],\"appDNSRule\": " +
			"[{\"dnsRuleId\": \"dnsRule1\",\"domainName\": \"www.example.com\",\"ipAddressType\":" +
			" \"IP_V4\",\"ipAddress\": \"192.0.1.0\", \"ttl\": 30,\"state\": \"ACTIVE\"}],\"appSupportMp1\": " +
			"true,\"appName\": \"abcd1\"}"
		invalidAddressType = "{\"appTrafficRule\": [{\"trafficRuleId\":\"TrafficRule2\",\"filterType\": \"FLOW\"," +
			"\"priority\": 2,\"trafficFilter\": [{\"srcAddress\": [\"192.168.1.1/28\"    ], \"dstAddress\":" +
			" [\"192.168.1.1/28\"],\"srcPort\": [\"8082\"],\"dstPort\": [\"8080\"], \"protocol\": [\"TCP\"],\"qCI\":" +
			" 1,\"dSCP\": 2,\"tC\": 1}],\"action\":\"DROP\",     \"state\": \"ACTIVE\"}],\"appDNSRule\": " +
			"[{\"dnsRuleId\": \"dnsRule2\",\"domainName\": \"www.example.com\",\"ipAddressType\":" +
			" \"IP\",\"ipAddress\": \"192.0.2.0\", \"ttl\": 30,\"state\": \"ACTIVE\"}],\"appSupportMp1\": " +
			"true,\"appName\": \"abcd2\"}"
		invalidAppName = "{\"appTrafficRule\": [{\"trafficRuleId\":\"TrafficRule3\",\"filterType\": \"FLOW\"," +
			"\"priority\": 1,\"trafficFilter\": [{\"srcAddress\": [\"192.168.1.1/28\"    ], \"dstAddress\":" +
			" [\"192.168.1.1/28\"],\"srcPort\": [\"8083\"],\"dstPort\": [\"8080\"], \"protocol\": [\"TCP\"],\"qCI\":" +
			" 1,\"dSCP\": 3,\"tC\": 1}],\"action\":\"DROP\",     \"state\": \"ACTIVE\"}],\"appDNSRule\": " +
			"[{\"dnsRuleId\": \"dnsRule3\",\"domainName\": \"www.example.com\",\"ipAddressType\":" +
			" \"IP_V4\",\"ipAddress\": \"192.0.3.0\", \"ttl\": 30,\"state\": \"ACTIVE\"}],\"appSupportMp1\": " +
			"true,\"appName\": \"_abcd\"}"
		invalidAction = "{\"appTrafficRule\": [{\"trafficRuleId\":\"TrafficRule4\",\"filterType\": \"FLOW\"," +
			"\"priority\": 3,\"trafficFilter\": [{\"srcAddress\": [\"192.168.1.1/28\"    ], \"dstAddress\":" +
			" [\"192.168.1.1/28\"],\"srcPort\": [\"8084\"],\"dstPort\": [\"8080\"], \"protocol\": [\"TCP\"],\"qCI\":" +
			" 1,\"dSCP\": 4,\"tC\": 1}],\"action\":\"DOP\",     \"state\": \"ACTIVE\"}],\"appDNSRule\": " +
			"[{\"dnsRuleId\": \"dnsRule5\",\"domainName\": \"www.example.com\",\"ipAddressType\":" +
			" \"IP_V4\",\"ipAddress\": \"192.0.4.0\", \"ttl\": 30,\"state\": \"ACTIVE\"}],\"appSupportMp1\": " +
			"true,\"appName\": \"abcd4\"}"
		ipv6Address = "{\"appTrafficRule\": [{\"trafficRuleId\":\"TrafficRule5\",\"filterType\": \"FLOW\"," +
			"\"priority\": 4,\"trafficFilter\": [{\"srcAddress\": [\"192.168.1.1/28\"    ], \"dstAddress\":" +
			" [\"192.168.1.1/28\"],\"srcPort\": [\"8085\"],\"dstPort\": [\"8080\"], \"protocol\": [\"TCP\"],\"qCI\":" +
			" 1,\"dSCP\": 5,\"tC\": 1}],\"action\":\"DROP\",     \"state\": \"ACTIVE\"}],\"appDNSRule\": " +
			"[{\"dnsRuleId\": \"dnsRule6\",\"domainName\": \"www.example.com\",\"ipAddressType\":" +
			" \"IP_V4\",\"ipAddress\": \"2001:0db8:85a3:0000:0000:8a2e:0370:7334\", \"ttl\": 30," +
			"\"state\": \"ACTIVE\"}],\"appSupportMp1\": " +
			"true,\"appName\": \"abcd5\"}"
		unMarshalAppRuleError = "failed to create appdrule model"
	)

	t.Run("TestInvalidFilterType", func(t *testing.T) {
		var appRuleConfig *models.AppdRule
		if err := json.Unmarshal([]byte(invalidFilterType), &appRuleConfig); err != nil {
			assert.Fail(t, unMarshalAppRuleError)
		}

		err := ValidateRestBody(appRuleConfig)
		assert.Error(t, err)
	})

	t.Run("TestInvalidPriority", func(t *testing.T) {
		var appRuleConfig *models.AppdRule
		if err := json.Unmarshal([]byte(invalidPriority), &appRuleConfig); err != nil {
			assert.Fail(t, unMarshalAppRuleError)
		}

		err := ValidateRestBody(appRuleConfig)
		assert.Error(t, err)
	})

	t.Run("TestInvalidAddressType", func(t *testing.T) {
		var appRuleConfig *models.AppdRule
		if err := json.Unmarshal([]byte(invalidAddressType), &appRuleConfig); err != nil {
			assert.Fail(t, unMarshalAppRuleError)
		}

		err := ValidateRestBody(appRuleConfig)
		assert.Error(t, err)
	})

	t.Run("TestInvalidAppName", func(t *testing.T) {
		var appRuleConfig *models.AppdRule
		if err := json.Unmarshal([]byte(invalidAppName), &appRuleConfig); err != nil {
			assert.Fail(t, unMarshalAppRuleError)
		}

		err := ValidateRestBody(appRuleConfig)
		assert.Error(t, err)
	})

	t.Run("TestInvalidAction", func(t *testing.T) {
		var appRuleConfig *models.AppdRule
		if err := json.Unmarshal([]byte(invalidAction), &appRuleConfig); err != nil {
			assert.Fail(t, unMarshalAppRuleError)
		}

		err := ValidateRestBody(appRuleConfig)
		assert.Error(t, err)
	})

	t.Run("TestIpv6address", func(t *testing.T) {
		var appRuleConfig *models.AppdRule
		if err := json.Unmarshal([]byte(ipv6Address), &appRuleConfig); err != nil {
			assert.Fail(t, unMarshalAppRuleError)
		}

		err := ValidateRestBody(appRuleConfig)
		assert.Nil(t, err)
	})
}

func TestValidateRestBody2(t *testing.T) {
	const (
		ipv4Addresss = "{\"appTrafficRule\": [{\"trafficRuleId\":\"TrafficRule6\",\"filterType\": \"FLOW\"," +
			"\"priority\": 5,\"trafficFilter\": [{\"srcAddress\": [\"192.168.1.1/28\"    ], \"dstAddress\":" +
			" [\"192.168.1.1/28\"],\"srcPort\": [\"8086\"],\"dstPort\": [\"8080\"], \"protocol\": [\"TCP\"],\"qCI\":" +
			" 1,\"dSCP\": 6,\"tC\": 1}],\"action\":\"DROP\",     \"state\": \"ACTIVE\"}],\"appDNSRule\": " +
			"[{\"dnsRuleId\": \"dnsRule7\",\"domainName\": \"www.example.com\",\"ipAddressType\":" +
			" \"IP_V4\",\"ipAddress\": \"256.256.256.256\", \"ttl\": 30,\"state\": \"ACTIVE\"}],\"appSupportMp1\": " +
			"true,\"appName\": \"abcd6\"}"
		invalidAddress = "{\"appTrafficRule\": [{\"trafficRuleId\":\"TrafficRule7\",\"filterType\": \"FLOW\"," +
			"\"priority\": 6,\"trafficFilter\": [{\"srcAddress\": [\"192.168.1.1/28\"    ], \"dstAddress\":" +
			" [\"192.168.1.1/28\"],\"srcPort\": [\"8087\"],\"dstPort\": [\"8080\"], \"protocol\": [\"TCP\"],\"qCI\":" +
			" 1,\"dSCP\": 7,\"tC\": 1}],\"action\":\"DROP\",     \"state\": \"ACTIVE\"}],\"appDNSRule\": " +
			"[{\"dnsRuleId\": \"dnsRule8\",\"domainName\": \"www.example.com\",\"ipAddressType\":" +
			" \"IP_V4\",\"ipAddress\": \"2001:0db8:85a3:0000:0000:8a2e:0370:7334:3445\", \"ttl\": 30,\"state\": \"ACTIVE\"}],\"appSupportMp1\": " +
			"true,\"appName\": \"abcd7\"}"
		invalidProtocol = "{\"appTrafficRule\": [{\"trafficRuleId\":\"TrafficRule8\",\"filterType\": \"FLOW\"," +
			"\"priority\": 7,\"trafficFilter\": [{\"srcAddress\": [\"192.168.1.1/28\"    ], \"dstAddress\":" +
			" [\"192.168.1.1/28\"],\"srcPort\": [\"8088\"],\"dstPort\": [\"8080\"], \"protocol\": [\"_TCP\"],\"qCI\":" +
			" 1,\"dSCP\": 8,\"tC\": 1}],\"action\":\"DROP\",     \"state\": \"ACTIVE\"}],\"appDNSRule\": " +
			"[{\"dnsRuleId\": \"dnsRule9\",\"domainName\": \"www.example.com\",\"ipAddressType\":" +
			" \"IP_V4\",\"ipAddress\": \"192.0.6.0\", \"ttl\": 30,\"state\": \"ACTIVE\"}],\"appSupportMp1\": " +
			"true,\"appName\": \"abcd8\"}"
		missingMandatoryParam = "{\"appTrafficRule\": [{\"trafficRuleId9\":\"TrafficRule1\",\"filterType\": \"FLOW\"," +
			"\"priority\": 8,\"trafficFilter\": [{\"srcAddress\": [\"192.168.1.1/28\"    ], \"dstAddress\":" +
			" [\"192.168.1.1/28\"],\"srcPort\": [\"8089\"],\"dstPort\": [\"8080\"], \"protocol\": [\"TCP\"],\"qCI\":" +
			" 1,\"dSCP\": 9,\"tC\": 1}],\"action\":\"DROP\",     \"state\": \"ACTIVE\"}],\"appDNSRule\": " +
			"[{\"dnsRuleId\": \"dnsRule10\",\"domainName\": \"www.example.com\",\"ipAddressType\":" +
			" \"IP_V4\",\"ipAddress\": \"192.0.7.0\", \"ttl\": 30,\"state\": \"ACTIVE\"}],\"appSupportMp1\": " +
			"true}"
		invalidSourceAddress = "{\"appTrafficRule\": [{\"trafficRuleId10\":\"TrafficRule1\",\"filterType\": \"FLOW\"," +
			"\"priority\": 9,\"trafficFilter\": [{\"srcAddress\": [\"192.168.1.1\"    ], \"dstAddress\":" +
			" [\"192.168.1.1/28\"],\"srcPort\": [\"8090\"],\"dstPort\": [\"8080\"], \"protocol\": [\"TCP\"],\"qCI\":" +
			" 1,\"dSCP\": 10,\"tC\": 1}],\"action\":\"DROP\",     \"state\": \"ACTIVE\"}],\"appDNSRule\": " +
			"[{\"dnsRuleId\": \"dnsRule11\",\"domainName\": \"www.example.com\",\"ipAddressType\":" +
			" \"IP_V4\",\"ipAddress\": \"192.0.8.0\", \"ttl\": 30,\"state\": \"ACTIVE\"}],\"appSupportMp1\": " +
			"true,\"appName\": \"abcd9\"}"
		unMarshalAppRuleError = "failed to create appdrule model"
	)

	t.Run("TestIpv4address", func(t *testing.T) {
		var appRuleConfig *models.AppdRule
		if err := json.Unmarshal([]byte(ipv4Addresss), &appRuleConfig); err != nil {
			assert.Fail(t, unMarshalAppRuleError)
		}

		err := ValidateRestBody(appRuleConfig)
		assert.Error(t, err)
	})

	t.Run("TestInvalidAddress", func(t *testing.T) {
		var appRuleConfig *models.AppdRule
		if err := json.Unmarshal([]byte(invalidAddress), &appRuleConfig); err != nil {
			assert.Fail(t, unMarshalAppRuleError)
		}

		err := ValidateRestBody(appRuleConfig)
		assert.Error(t, err)
	})

	t.Run("TestMissingMandatoryParam", func(t *testing.T) {
		var appRuleConfig *models.AppdRule
		if err := json.Unmarshal([]byte(missingMandatoryParam), &appRuleConfig); err != nil {
			assert.Fail(t, unMarshalAppRuleError)
		}

		err := ValidateRestBody(appRuleConfig)
		assert.Error(t, err)
	})

	t.Run("TestInvalidProtocol", func(t *testing.T) {
		var appRuleConfig *models.AppdRule
		if err := json.Unmarshal([]byte(invalidProtocol), &appRuleConfig); err != nil {
			assert.Fail(t, unMarshalAppRuleError)
		}

		err := ValidateRestBody(appRuleConfig)
		assert.Error(t, err)
	})

	t.Run("TestInvalidSrcAddress", func(t *testing.T) {
		var appRuleConfig *models.AppdRule
		if err := json.Unmarshal([]byte(invalidSourceAddress), &appRuleConfig); err != nil {
			assert.Fail(t, unMarshalAppRuleError)
		}

		err := ValidateRestBody(appRuleConfig)
		assert.Error(t, err)
	})

	t.Run("TestValidateName", func(t *testing.T) {
		_, err := ValidateName("abcd5abcd5abcd5abcd5abcd5abcd5abcd5abcd5abcd5abcd5abcd5abcd5abcd5abcd5abcd5"+
			"abcd5abcd5abcd5abcd5abcd5abcd5abcd5abcd5abcd5abcd5abcd5abcd5abcd5abcd5", NameRegex)
		assert.Equal(t, "name length is larger than max size", err.Error())
	})

	t.Run("TestTLSConfig1", func(t *testing.T) {
		getwd, _ := os.Getwd()
		beego.AppConfig.Set("certName", getwd + "/server.crt")
		beego.AppConfig.Set("ssl_ciphers",
			"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")
		crtName := "certName"
		_, err := TLSConfig(crtName)
		//assert.Nil(t, (t, "TLS cipher configuration is not recommended or invalid", err.Error(), "TestTLSConfig execution result"))
		assert.Nil(t, err,"TestTLSConfig1 execution result")
	})

	t.Run("TestTLSConfig2", func(t *testing.T) {
		getwd, _ := os.Getwd()
		beego.AppConfig.Set("certName", getwd + "/server1.crt")
		crtName := "certName"
		_, err := TLSConfig(crtName)
		assert.NotNil(t, err,"TestTLSConfig2 execution result")
	})

	t.Run("TestTLSConfig3", func(t *testing.T) {
		getwd, _ := os.Getwd()
		beego.AppConfig.Set("certName", getwd + "/server.crt")
		beego.AppConfig.Set("ssl_ciphers","")
		crtName := "certName"
		_, err := TLSConfig(crtName)
		assert.Equal(t, "TLS cipher configuration is not recommended or invalid", err.Error(),"TestTLSConfig3 execution result")
	})

	t.Run("TestTLSConfig4", func(t *testing.T) {
		getwd, _ := os.Getwd()
		beego.AppConfig.Set("certName", getwd + "/server.crt")
		beego.AppConfig.Set("ssl_ciphers",", TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")
		crtName := "certName"
		_, err := TLSConfig(crtName)
		assert.Nil(t, err,"TestTLSConfig4 execution result")
	})

	t.Run("TestTLSConfig5", func(t *testing.T) {
		getwd, _ := os.Getwd()
		beego.AppConfig.Set("certName", getwd + "/server.crt")
		beego.AppConfig.Set("ssl_ciphers",", ")
		crtName := "certName"
		_, err := TLSConfig(crtName)
		assert.Equal(t, "TLS cipher configuration is not recommended or invalid", err.Error(),"TestTLSConfig5 execution result")
	})

	t.Run("DoRequest", func(t *testing.T) {

		url := "http://" + "127.0.0.1" + ":" + "80" + "/example"
		req, _ := http.NewRequest("DELETE", url, nil)

		getwd, _ := os.Getwd()
		beego.AppConfig.Set("SSL_ROOT_CERT", getwd + "/server.crt")
		beego.AppConfig.Set("ssl_ciphers",
			"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")
		_, err := DoRequest(req)
		assert.NotNil(t, err,"DoRequest execution result")
	})


	t.Run("ValidateRegexp", func(t *testing.T) {
		err := ValidateRegexp("abcdef", "a]{1}[b]{1}[abc|cab|bca|acb|ac|ca|ab|bc|cb][b]{1}[a]{1}$", "failed to validate string")
		assert.NotNil(t, err,"ValidateRegexp execution result")
	})

}
