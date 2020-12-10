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

package controllers

import (
	"bytes"
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"mecm-apprulemgr/models"
	"mecm-apprulemgr/util"
	"net/http"
	"testing"
)

func TestAppRuleFacade(t *testing.T) {
	t.Run("TestAppRulePostSuccess", func(t *testing.T) {
		// mock response
		progressModel := "{\n  \"taskId \": \"51ea862b-5806-4196-bce3-434bf9c95b18\",\n " +
			" \"appInstanceId\": \"71ea862b-5806-4196-bce3-434bf9c95b18\",\n  " +
			"\"configResult\": \"SUCCESS\",\n  \"configPhase\": \"0\",\n  \"detailed\": \"\"\n}"
		httpResponse := &http.Response{
			Status:     "200 OK",
			StatusCode: 200,
			Body:       ioutil.NopCloser(bytes.NewBufferString(progressModel)),
		}

		// mock rest client
		restClientMock := RestClientMock{}
		restClientMock.On("sendRequest").Return(httpResponse, nil)

		// create app rule facade
		appRuleFacade := &AppRuleFacade{
			restClient:    &restClientMock,
			appInstanceId: "71ea862b-5806-4196-bce3-434bf9c95b18",
		}

		response, _ := appRuleFacade.handleAppRuleRequest()

		// verify response
		assert.Equal(t, response.code, 200)
		assert.Equal(t, response.progressModel.ConfigResult, "SUCCESS")
	})

	t.Run("TestAppRulePostFailure", func(t *testing.T) {
		// mock response
		progressModel := "{\n  \"taskId \": \"51ea862b-5806-4196-bce3-434bf9c95b18\",\n " +
			" \"appInstanceId\": \"71ea862b-5806-4196-bce3-434bf9c95b18\",\n  " +
			"\"configResult\": \"FAILURE\",\n  \"configPhase\": \"0\",\n  \"detailed\": \"\"\n}"
		httpResponse := &http.Response{
			StatusCode: 200,
			Body:       ioutil.NopCloser(bytes.NewBufferString(progressModel)),
		}

		// mock rest client
		restClientMock := RestClientMock{}
		restClientMock.On("sendRequest").Return(httpResponse, nil)

		// create app rule facade
		appRuleFacade := &AppRuleFacade{
			restClient:    &restClientMock,
			appInstanceId: "71ea862b-5806-4196-bce3-434bf9c95b18",
		}

		response, _ := appRuleFacade.handleAppRuleRequest()

		// verify response
		assert.Equal(t, response.code, 500)
		assert.Equal(t, response.progressModel.ConfigResult, "FAILURE")
	})

	t.Run("TestTaskQueryFailureModel", func(t *testing.T) {
		// mock response
		failureModel := "{\n  \"type\": \"error\",\n  \"title\": \"config error\",\n  \"status\": 5,\n " +
			" \"detail\": \"duplicate entry\"\n}"
		httpResponse := &http.Response{
			StatusCode: 400,
			Body:       ioutil.NopCloser(bytes.NewBufferString(failureModel)),
		}

		// mock rest client
		restClientMock := RestClientMock{}
		restClientMock.On("sendRequest").Return(httpResponse, nil)

		// create app rule facade
		appRuleFacade := &AppRuleFacade{
			restClient:    &restClientMock,
			appInstanceId: "71ea862b-5806-4196-bce3-434bf9c95b18",
		}

		response, _ := appRuleFacade.handleAppRuleRequest()
		assert.Equal(t, response.code, 400)
		assert.Equal(t, response.progressModel.ConfigResult, "FAILURE")
		assert.Equal(t, response.progressModel.Detailed, "duplicate entry")
	})

	t.Run("TestAppRuleConfigInProgress", func(t *testing.T) {
		// mock response
		progressModel := "{\n  \"taskId \": \"51ea862b-5806-4196-bce3-434bf9c95b18\",\n " +
			" \"appInstanceId\": \"71ea862b-5806-4196-bce3-434bf9c95b18\",\n  " +
			"\"configResult\": \"PROCESSING\",\n  \"configPhase\": \"0\",\n  \"detailed\": \"\"\n}"
		httpResponse := &http.Response{
			StatusCode: 200,
			Body:       ioutil.NopCloser(bytes.NewBufferString(progressModel)),
		}

		// mock rest client
		restClientMock := RestClientMock{}
		restClientMock.On("sendRequest").Return(httpResponse, nil)

		// create app rule facade
		appRuleFacade := &AppRuleFacade{
			restClient:    &restClientMock,
			appInstanceId: "71ea862b-5806-4196-bce3-434bf9c95b18",
		}

		_, err := appRuleFacade.handleAppRuleRequest()
		assert.Equal(t, err.Error(), "cert name configuration is not set")
	})

	t.Run("TestAppRuleConfigGetRequest", func(t *testing.T) {
		// mock response
		appdModel := "{\n  \"appTrafficRule\": [\n    {\n" +
			"\"trafficRuleId\": \"TrafficRule1\",\n" +
			"\"filterType\": \"FLOW\",\n" +
			"\"priority\": 1,\n" +
			"\"trafficFilter\": [\n {\n" +
			"\"srcAddress\": [\n" + "\"192.168.1.1/28\"\n],\n" +
			"\"dstAddress\": [\n\"192.168.1.1/28\"\n],\n" +
			"\"srcPort\": [\n\"8080\"\n],\n" +
			"\"dstPort\": [\n\"8080\"\n],\n" +
			"\"protocol\": [\n\"TCP\"\n],\n" +
			"\"qCI\": 1,\n\"dSCP\": 0,\n\"tC\": 1\n}\n],\n\"action\": \"DROP\",\n" +
			"\"state\": \"ACTIVE\"\n}\n],\n" +
			"\"appDNSRule\":[\n{\n" +
			"\"dnsRuleId\": \"dnsRule4\",\n\"domainName\": \"www.example.com\"," +
			"\n\"ipAddressType\": \"IP_V4\",\n\"ipAddress\": \"192.0.2.0\",\n\"ttl\": 30," +
			"\n\"state\": \"ACTIVE\"\n}\n  ],\n  \"appSupportMp1\": true,\n  \"appName\": \"abcd\"\n}"
		httpResponse := &http.Response{
			StatusCode: 200,
			Body:       ioutil.NopCloser(bytes.NewBufferString(appdModel)),
		}

		// mock rest client
		restClientMock := RestClientMock{}
		restClientMock.On("sendRequest").Return(httpResponse, nil)

		// create app rule facade
		appRuleFacade := &AppRuleFacade{
			restClient:    &restClientMock,
			appInstanceId: "71ea862b-5806-4196-bce3-434bf9c95b18",
		}

		response, _ := appRuleFacade.handleAppRuleGetRequest()
		assert.Equal(t, response.code, 200)
	})

	t.Run("TestAppRuleGetFailureModel", func(t *testing.T) {
		// mock response
		failureModel := "{\n  \"type\": \"error\",\n  \"title\": \"config error\",\n  \"status\": 5,\n " +
			" \"detail\": \"not found\"\n}"
		httpResponse := &http.Response{
			StatusCode: 404,
			Body:       ioutil.NopCloser(bytes.NewBufferString(failureModel)),
		}

		// mock rest client
		restClientMock := RestClientMock{}
		restClientMock.On("sendRequest").Return(httpResponse, nil)

		// create app rule facade
		appRuleFacade := &AppRuleFacade{
			restClient:    &restClientMock,
			appInstanceId: "71ea862b-5806-4196-bce3-434bf9c95b18",
		}

		response, _ := appRuleFacade.handleAppRuleGetRequest()
		assert.Equal(t, response.code, 404)
		assert.Equal(t, response.progressModel.ConfigResult, "FAILURE")
		assert.Equal(t, response.progressModel.Detailed, "not found")
	})

	t.Run("TestCreateAppRuleFacade", func(t *testing.T) {
		restClient, _ := createRestClient(util.CreateAppdRuleUrl("71ea862b-5806-4196-bce3-434bf9c95b18"), util.Get, nil)
		appRuleFacade := createAppRuleFacade(restClient, "71ea862b-5806-4196-bce3-434bf9c95b18")
		assert.Equal(t, appRuleFacade.appInstanceId, "71ea862b-5806-4196-bce3-434bf9c95b18")
	})

	t.Run("TestCreateRestClientForPostRequest", func(t *testing.T) {
		appdModel := "{\n  \"appTrafficRule\": [\n    {\n" +
			"\"trafficRuleId\": \"TrafficRule1\",\n" +
			"\"filterType\": \"FLOW\",\n" +
			"\"priority\": 1,\n" +
			"\"trafficFilter\": [\n {\n" +
			"\"srcAddress\": [\n" + "\"192.168.1.1/28\"\n],\n" +
			"\"dstAddress\": [\n\"192.168.1.1/28\"\n],\n" +
			"\"srcPort\": [\n\"8080\"\n],\n" +
			"\"dstPort\": [\n\"8080\"\n],\n" +
			"\"protocol\": [\n\"TCP\"\n],\n" +
			"\"qCI\": 1,\n\"dSCP\": 0,\n\"tC\": 1\n}\n],\n\"action\": \"DROP\",\n" +
			"\"state\": \"ACTIVE\"\n}\n],\n" +
			"\"appDNSRule\":[\n{\n" +
			"\"dnsRuleId\": \"dnsRule4\",\n\"domainName\": \"www.example.com\"," +
			"\n\"ipAddressType\": \"IP_V4\",\n\"ipAddress\": \"192.0.2.0\",\n\"ttl\": 30," +
			"\n\"state\": \"ACTIVE\"\n}\n  ],\n  \"appSupportMp1\": true,\n  \"appName\": \"abcd\"\n}"
		appdModelBytes := []byte(appdModel)
		var rule *models.AppdRule
		_ = json.Unmarshal(appdModelBytes, &rule)
		restClient, _ := createRestClient(util.CreateAppdRuleUrl("71ea862b-5806-4196-bce3-434bf9c95b18"),
			util.Post, rule)
		assert.Equal(t, restClient.method, util.Post)
	})

	t.Run("TestCreateRestClientForPutRequest", func(t *testing.T) {
		appdModel := "{\n  \"appTrafficRule\": [\n    {\n" +
			"\"trafficRuleId\": \"TrafficRule1\",\n" +
			"\"filterType\": \"FLOW\",\n" +
			"\"priority\": 1,\n" +
			"\"trafficFilter\": [\n {\n" +
			"\"srcAddress\": [\n" + "\"192.168.1.1/28\"\n],\n" +
			"\"dstAddress\": [\n\"192.168.1.1/28\"\n],\n" +
			"\"srcPort\": [\n\"8080\"\n],\n" +
			"\"dstPort\": [\n\"8080\"\n],\n" +
			"\"protocol\": [\n\"TCP\"\n],\n" +
			"\"qCI\": 1,\n\"dSCP\": 0,\n\"tC\": 1\n}\n],\n\"action\": \"DROP\",\n" +
			"\"state\": \"ACTIVE\"\n}\n],\n" +
			"\"appDNSRule\":[\n{\n" +
			"\"dnsRuleId\": \"dnsRule4\",\n\"domainName\": \"www.example.com\"," +
			"\n\"ipAddressType\": \"IP_V4\",\n\"ipAddress\": \"192.0.2.0\",\n\"ttl\": 30," +
			"\n\"state\": \"ACTIVE\"\n}\n  ],\n  \"appSupportMp1\": true,\n  \"appName\": \"abcd\"\n}"
		appdModelBytes := []byte(appdModel)
		var rule *models.AppdRule
		_ = json.Unmarshal(appdModelBytes, &rule)
		restClient, _ := createRestClient(util.CreateAppdRuleUrl("71ea862b-5806-4196-bce3-434bf9c95b18"),
			util.Put, rule)
		assert.Equal(t, restClient.method, util.Put)
	})

	t.Run("TestCreateRestClientForDeleteRequest", func(t *testing.T) {
		restClient, _ := createRestClient(util.CreateAppdRuleUrl("71ea862b-5806-4196-bce3-434bf9c95b18"),
			util.Delete, nil)
		assert.Equal(t, restClient.method, util.Delete)
	})

	t.Run("TestCreateRestClientForUnknownMethod", func(t *testing.T) {
		_, err := createRestClient(util.CreateAppdRuleUrl("71ea862b-5806-4196-bce3-434bf9c95b18"),
			"unknown", nil)
		assert.Equal(t, err.Error(), "unknown rest method")
	})
}
