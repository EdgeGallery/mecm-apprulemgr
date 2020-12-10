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
	"github.com/dgrijalva/jwt-go"
	"github.com/stretchr/testify/assert"
	"mecm-apprulemgr/models"
	"testing"
	"time"
)

func createToken(userid uint64) string {
	//Creating Access Token
	atClaims := jwt.MapClaims{}
	roleName := make([]string, 3)
	roleName[0] = "ROLE_MECM_TENANT"
	roleName[1] = "ROLE_APPSTORE_TENANT"
	roleName[2] = "ROLE_DEVELOPER_TENANT"
	atClaims["authorities"] = roleName
	atClaims["user_name"] = "lcmcontroller"
	atClaims["authorized"] = true
	atClaims["userId"] = userid
	atClaims["exp"] = time.Now().Add(time.Minute * 60).Unix()
	at := jwt.NewWithClaims(jwt.SigningMethodHS256, atClaims)
	token, _ := at.SignedString([]byte("jdnfksdmfksd"))
	return token
}

func TestValidateAccessTokenSuccess(t *testing.T) {
	accessToken := createToken(1)
	err := ValidateAccessToken(accessToken, []string{MecmTenantRole})
	assert.Nil(t, err, "TestValidateAccessTokenSuccess execution result")
}

func TestValidateAccessTokenFailure(t *testing.T) {
	accessToken := ""
	err := ValidateAccessToken(accessToken, []string{MecmTenantRole})
	assert.Error(t, err, "TestValidateAccessTokenFailure execution result")
}

func TestValidateAccessTokenInvalid(t *testing.T) {
	accessToken := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"
	err := ValidateAccessToken(accessToken, []string{MecmTenantRole})
	assert.Error(t, err, "TestValidateAccessTokenInvalid execution result")
}

func TestValidateAccessTokenInvalid1(t *testing.T) {
	accessToken := "eyJ1c2VyX25hbWUiOiI3MjY5NjM4ZS01NjM3LTRiOGMtODE3OC1iNTExMmJhN2I2OWIiLCJzY29wZSI6WyJhbGwiXSwiZ" +
		"XhwIjoxNTk5Mjc5NDA3LCJzc29TZXNzaW9uSWQiOiI1QkYwNjM2QzlBMkEzMUI2NEEwMEFCRTk1OTVEN0E0NyIsInVzZXJOYW1lIjoid" +
		"2Vuc29uIiwidXNlcklkIjoiNzI2OTYzOGUtNTYzNy00YjhjLTgxNzgtYjUxMTJiYTdiNjliIiwiYXV0aG9yaXRpZXMiOlsiUk9MRV9BU" +
		"FBTVE9SRV9URU5BTlQiLCJST0xFX0RFVkVMT1BFUl9URU5BTlQiLCJST0xFX01FQ01fVEVOQU5UIl0sImp0aSI6IjQ5ZTBhMGMwLTIxZ" +
		"mItNDAwZC04M2MyLTI3NzIwNWQ1ZTY3MCIsImNsaWVudF9pZCI6Im1lY20tZmUiLCJlbmFibGVTbXMiOiJ0cnVlIn0."
	err := ValidateAccessToken(accessToken, []string{MecmTenantRole})
	assert.Error(t, err, "TestValidateAccessTokenInvalid1 execution result")
}

func TestValidateIpv4AddressSuccess(t *testing.T) {
	ip := "1.2.3.4"
	err := ValidateIpv4Address(ip)
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
		invalidFilterType = "{\"appTrafficRule\": [{\"trafficRuleId\":\"TrafficRule1\",\"filterType\": \"LOW\"," +
			"\"priority\": 1,\"trafficFilter\": [{\"srcAddress\": [\"192.168.1.1/28\"    ], \"dstAddress\":" +
			" [\"192.168.1.1/28\"],\"srcPort\": [\"8080\"],\"dstPort\": [\"8080\"], \"protocol\": [\"TCP\"],\"qCI\":" +
			" 1,\"dSCP\": 0,\"tC\": 1}],\"action\":\"DROP\",     \"state\": \"ACTIVE\"}],\"appDNSRule\": " +
			"[{\"dnsRuleId\": \"dnsRule4\",\"domainName\": \"www.example.com\",\"ipAddressType\":" +
			" \"IP_V4\",\"ipAddress\": \"192.0.2.0\", \"ttl\": 30,\"state\": \"ACTIVE\"}],\"appSupportMp1\": " +
			"true,\"appName\": \"abcd\"}"
		invalidPriority = "{\"appTrafficRule\": [{\"trafficRuleId\":\"TrafficRule1\",\"filterType\": \"FLOW\"," +
			"\"priority\": 0,\"trafficFilter\": [{\"srcAddress\": [\"192.168.1.1/28\"    ], \"dstAddress\":" +
			" [\"192.168.1.1/28\"],\"srcPort\": [\"8080\"],\"dstPort\": [\"8080\"], \"protocol\": [\"TCP\"],\"qCI\":" +
			" 1,\"dSCP\": 0,\"tC\": 1}],\"action\":\"DROP\",     \"state\": \"ACTIVE\"}],\"appDNSRule\": " +
			"[{\"dnsRuleId\": \"dnsRule4\",\"domainName\": \"www.example.com\",\"ipAddressType\":" +
			" \"IP_V4\",\"ipAddress\": \"192.0.2.0\", \"ttl\": 30,\"state\": \"ACTIVE\"}],\"appSupportMp1\": " +
			"true,\"appName\": \"abcd\"}"
		invalidAddressType = "{\"appTrafficRule\": [{\"trafficRuleId\":\"TrafficRule1\",\"filterType\": \"FLOW\"," +
			"\"priority\": 1,\"trafficFilter\": [{\"srcAddress\": [\"192.168.1.1/28\"    ], \"dstAddress\":" +
			" [\"192.168.1.1/28\"],\"srcPort\": [\"8080\"],\"dstPort\": [\"8080\"], \"protocol\": [\"TCP\"],\"qCI\":" +
			" 1,\"dSCP\": 0,\"tC\": 1}],\"action\":\"DROP\",     \"state\": \"ACTIVE\"}],\"appDNSRule\": " +
			"[{\"dnsRuleId\": \"dnsRule4\",\"domainName\": \"www.example.com\",\"ipAddressType\":" +
			" \"IP\",\"ipAddress\": \"192.0.2.0\", \"ttl\": 30,\"state\": \"ACTIVE\"}],\"appSupportMp1\": " +
			"true,\"appName\": \"abcd\"}"
		invalidAppName = "{\"appTrafficRule\": [{\"trafficRuleId\":\"TrafficRule1\",\"filterType\": \"FLOW\"," +
			"\"priority\": 1,\"trafficFilter\": [{\"srcAddress\": [\"192.168.1.1/28\"    ], \"dstAddress\":" +
			" [\"192.168.1.1/28\"],\"srcPort\": [\"8080\"],\"dstPort\": [\"8080\"], \"protocol\": [\"TCP\"],\"qCI\":" +
			" 1,\"dSCP\": 0,\"tC\": 1}],\"action\":\"DROP\",     \"state\": \"ACTIVE\"}],\"appDNSRule\": " +
			"[{\"dnsRuleId\": \"dnsRule4\",\"domainName\": \"www.example.com\",\"ipAddressType\":" +
			" \"IP_V4\",\"ipAddress\": \"192.0.2.0\", \"ttl\": 30,\"state\": \"ACTIVE\"}],\"appSupportMp1\": " +
			"true,\"appName\": \"_abcd\"}"
		invalidAction = "{\"appTrafficRule\": [{\"trafficRuleId\":\"TrafficRule1\",\"filterType\": \"FLOW\"," +
			"\"priority\": 1,\"trafficFilter\": [{\"srcAddress\": [\"192.168.1.1/28\"    ], \"dstAddress\":" +
			" [\"192.168.1.1/28\"],\"srcPort\": [\"8080\"],\"dstPort\": [\"8080\"], \"protocol\": [\"TCP\"],\"qCI\":" +
			" 1,\"dSCP\": 0,\"tC\": 1}],\"action\":\"DOP\",     \"state\": \"ACTIVE\"}],\"appDNSRule\": " +
			"[{\"dnsRuleId\": \"dnsRule4\",\"domainName\": \"www.example.com\",\"ipAddressType\":" +
			" \"IP_V4\",\"ipAddress\": \"192.0.2.0\", \"ttl\": 30,\"state\": \"ACTIVE\"}],\"appSupportMp1\": " +
			"true,\"appName\": \"abcd\"}"
		ipv6Address = "{\"appTrafficRule\": [{\"trafficRuleId\":\"TrafficRule1\",\"filterType\": \"FLOW\"," +
			"\"priority\": 1,\"trafficFilter\": [{\"srcAddress\": [\"192.168.1.1/28\"    ], \"dstAddress\":" +
			" [\"192.168.1.1/28\"],\"srcPort\": [\"8080\"],\"dstPort\": [\"8080\"], \"protocol\": [\"TCP\"],\"qCI\":" +
			" 1,\"dSCP\": 0,\"tC\": 1}],\"action\":\"DROP\",     \"state\": \"ACTIVE\"}],\"appDNSRule\": " +
			"[{\"dnsRuleId\": \"dnsRule4\",\"domainName\": \"www.example.com\",\"ipAddressType\":" +
			" \"IP_V4\",\"ipAddress\": \"2001:0db8:85a3:0000:0000:8a2e:0370:7334\", \"ttl\": 30," +
			"\"state\": \"ACTIVE\"}],\"appSupportMp1\": " +
			"true,\"appName\": \"abcd\"}"
		ipv4Addresss = "{\"appTrafficRule\": [{\"trafficRuleId\":\"TrafficRule1\",\"filterType\": \"FLOW\"," +
			"\"priority\": 1,\"trafficFilter\": [{\"srcAddress\": [\"192.168.1.1/28\"    ], \"dstAddress\":" +
			" [\"192.168.1.1/28\"],\"srcPort\": [\"8080\"],\"dstPort\": [\"8080\"], \"protocol\": [\"TCP\"],\"qCI\":" +
			" 1,\"dSCP\": 0,\"tC\": 1}],\"action\":\"DROP\",     \"state\": \"ACTIVE\"}],\"appDNSRule\": " +
			"[{\"dnsRuleId\": \"dnsRule4\",\"domainName\": \"www.example.com\",\"ipAddressType\":" +
			" \"IP_V4\",\"ipAddress\": \"256.256.256.256\", \"ttl\": 30,\"state\": \"ACTIVE\"}],\"appSupportMp1\": " +
			"true,\"appName\": \"abcd\"}"
		invalidAddress = "{\"appTrafficRule\": [{\"trafficRuleId\":\"TrafficRule1\",\"filterType\": \"FLOW\"," +
			"\"priority\": 1,\"trafficFilter\": [{\"srcAddress\": [\"192.168.1.1/28\"    ], \"dstAddress\":" +
			" [\"192.168.1.1/28\"],\"srcPort\": [\"8080\"],\"dstPort\": [\"8080\"], \"protocol\": [\"TCP\"],\"qCI\":" +
			" 1,\"dSCP\": 0,\"tC\": 1}],\"action\":\"DROP\",     \"state\": \"ACTIVE\"}],\"appDNSRule\": " +
			"[{\"dnsRuleId\": \"dnsRule4\",\"domainName\": \"www.example.com\",\"ipAddressType\":" +
			" \"IP_V4\",\"ipAddress\": \"2001:0db8:85a3:0000:0000:8a2e:0370:7334:3445\", \"ttl\": 30,\"state\": \"ACTIVE\"}],\"appSupportMp1\": " +
			"true,\"appName\": \"abcd\"}"
		invalidProtocol = "{\"appTrafficRule\": [{\"trafficRuleId\":\"TrafficRule1\",\"filterType\": \"FLOW\"," +
			"\"priority\": 1,\"trafficFilter\": [{\"srcAddress\": [\"192.168.1.1/28\"    ], \"dstAddress\":" +
			" [\"192.168.1.1/28\"],\"srcPort\": [\"8080\"],\"dstPort\": [\"8080\"], \"protocol\": [\"_TCP\"],\"qCI\":" +
			" 1,\"dSCP\": 0,\"tC\": 1}],\"action\":\"DROP\",     \"state\": \"ACTIVE\"}],\"appDNSRule\": " +
			"[{\"dnsRuleId\": \"dnsRule4\",\"domainName\": \"www.example.com\",\"ipAddressType\":" +
			" \"IP_V4\",\"ipAddress\": \"192.0.2.0\", \"ttl\": 30,\"state\": \"ACTIVE\"}],\"appSupportMp1\": " +
			"true,\"appName\": \"abcd\"}"
		missingMandatoryParam = "{\"appTrafficRule\": [{\"trafficRuleId\":\"TrafficRule1\",\"filterType\": \"FLOW\"," +
			"\"priority\": 1,\"trafficFilter\": [{\"srcAddress\": [\"192.168.1.1/28\"    ], \"dstAddress\":" +
			" [\"192.168.1.1/28\"],\"srcPort\": [\"8080\"],\"dstPort\": [\"8080\"], \"protocol\": [\"TCP\"],\"qCI\":" +
			" 1,\"dSCP\": 0,\"tC\": 1}],\"action\":\"DROP\",     \"state\": \"ACTIVE\"}],\"appDNSRule\": " +
			"[{\"dnsRuleId\": \"dnsRule4\",\"domainName\": \"www.example.com\",\"ipAddressType\":" +
			" \"IP_V4\",\"ipAddress\": \"192.0.2.0\", \"ttl\": 30,\"state\": \"ACTIVE\"}],\"appSupportMp1\": " +
			"true}"
		invalidSourceAddress = "{\"appTrafficRule\": [{\"trafficRuleId\":\"TrafficRule1\",\"filterType\": \"FLOW\"," +
			"\"priority\": 1,\"trafficFilter\": [{\"srcAddress\": [\"192.168.1.1\"    ], \"dstAddress\":" +
			" [\"192.168.1.1/28\"],\"srcPort\": [\"8080\"],\"dstPort\": [\"8080\"], \"protocol\": [\"TCP\"],\"qCI\":" +
			" 1,\"dSCP\": 0,\"tC\": 1}],\"action\":\"DROP\",     \"state\": \"ACTIVE\"}],\"appDNSRule\": " +
			"[{\"dnsRuleId\": \"dnsRule4\",\"domainName\": \"www.example.com\",\"ipAddressType\":" +
			" \"IP_V4\",\"ipAddress\": \"192.0.2.0\", \"ttl\": 30,\"state\": \"ACTIVE\"}],\"appSupportMp1\": " +
			"true,\"appName\": \"abcd\"}"
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
}
