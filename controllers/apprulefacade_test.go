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
	"github.com/astaxie/beego"
	"github.com/astaxie/beego/context"
	"github.com/stretchr/testify/assert"
	"github.com/ulule/limiter/v3"
	"github.com/ulule/limiter/v3/drivers/store/memory"
	"io/ioutil"
	"mecm-apprulemgr/models"
	"mecm-apprulemgr/util"
	"net/http"
	"net/http/httptest"
	"testing"
)

const (
	FailureResponse = "{\n  \"taskId \": \"51ea862b-5806-4196-bce3-434bf9c95b18\",\n " +
		" \"appInstanceId\": \"71ea862b-5806-4196-bce3-434bf9c95b18\",\n  " +
		"\"configResult\": \"FAILURE\",\n  \"configPhase\": \"0\",\n  \"detailed\": \"\"\n}"
	SuccessResponse = "{\n  \"taskId \": \"51ea862b-5806-4196-bce3-434bf9c95b19\",\n " +
		" \"appInstanceId\": \"71ea862b-5806-4196-bce3-434bf9c95b19\",\n  " +
		"\"configResult\": \"SUCCESS\",\n  \"configPhase\": \"0\",\n  \"detailed\": \"\"\n}"
	InProgressResponse = "{\n  \"taskId \": \"51ea862b-5806-4196-bce3-434bf9c95b17\",\n " +
		" \"appInstanceId\": \"71ea862b-5806-4196-bce3-434bf9c95b17\",\n  " +
		"\"configResult\": \"PROCESSING\",\n  \"configPhase\": \"0\",\n  \"detailed\": \"\"\n}"
	MepFailureResponse = "{\n  \"type\": \"error\",\n  \"title\": \"config error\",\n  \"status\": 5,\n " +
		" \"detail\": \"duplicate entry\"\n}"
	NotFoundResponse = "{\n  \"type\": \"error\",\n  \"title\": \"config error\",\n  \"status\": 5,\n " +
		" \"detail\": \"not found\"\n}"
	AppRule   string = "{\n\"appdRuleId\":" +
		"\"e921ce54-82c8-4532-b5c6-8516cf75f7a771ea862b-5806-4196-bce3-434bf9c95b18\",\n\"tenantId\":" +
		"\"e921ce54-82c8-4532-b5c6-8516cf75f7a7\",\n\"appInstanceId\":\"71ea862b-5806-4196-bce3-434bf9c95b18\",\n\"" +
		"appName\":\"abcd\",\n\"appSupportMp1\": true,\n\"appTrafficRule\": [\n{\n\"trafficRuleId\":\"TrafficRule1\",\n\"" +
		"filterType\":\"FLOW\",\n\"priority\": 1,\n\"action\":\"DROP\",\n\"trafficFilter\":[\n{\n\"trafficFilterId\":" +
		"\"75256a74-adb9-4c6d-8246-9773dfd5f6df\",\n\"srcAddress\":[\n\"192.168.1.1/28\",\n\"192.168.1.2/28\"\n],\n\"" +
		"srcPort\":[\n\"6666666666\"\n],\n\"dstAddress\":[\n\"192.168.1.1/28\"\n],\n\"dstPort\":[\n\"6666666666\"\n],\n\"" +
		"protocol\":[\n\"TCP\"\n],\n\"qCI\": 1,\n\"dSCP\":0,\n\"tC\": 1,\n\"tag\":[\n\"1\"\n],\n\"srcTunnelAddress\":" +
		"[\n\"1.1.1.1/24\"\n],\n\"dstTunnelAddress\":[\n\"1.1.1.1/24\"\n],\n\"srcTunnelPort\":[\n\"65536\"\n],\n\"" +
		"dstTunnelPort\":[\n\"65537\"\n]\n}\n],\n\"dstInterface\":[\n{\n\"dstInterfaceId\":" +
		"\"caf2dab7-0c20-4fe7-ac72-a7e204a309d2\",\n\"interfaceType\":\"\",\n\"srcMacAddress\":\"\",\n\"dstMacAddress\":" +
		"\"\",\n\"dstIpAddress\":\"\",\n\"TunnelInfo\":{\n\"tunnelInfoId\":\"461ceb53-291c-422c-9cbe-27f40e4ad2b3\",\n\"" +
		"tunnelType\":\"\",\n\"tunnelDstAddress\":\"\",\n\"tunnelSrcAddress\":\"\",\n\"tunnelSpecificData\":" +
		"\"\"\n}\n}\n]\n}\n],\n\"appDnsRule\":[\n{\n\"dnsRuleId\":\"dnsRule4\",\n\"domainName\":\"www.example.com\",\n\"" +
		"ipAddressType\":\"IP_V4\",\n\"ipAddress\":\"192.0.2.0\",\n\"ttl\":30\n}\n],\n\"Origin\":\"MEPM\"\n}"
	AppInstanceId = "71ea862b-5806-4196-bce3-434bf9c95b18"
	TaskId        = "51ea862b-5806-4196-bce3-434bf9c95b18"
	Success       = "SUCCESS"
	Failure       = "FAILURE"
	SendRequest   = "sendRequest"
)

func TestAppRuleFacade(t *testing.T) {
	t.Run("TestAppRulePostSuccess", func(t *testing.T) {
		httpResponse := &http.Response{
			Status:     "200 OK",
			StatusCode: 200,
			Body:       ioutil.NopCloser(bytes.NewBufferString(SuccessResponse)),
		}

		// mock rest client
		restClientMock := RestClientMock{}
		restClientMock.On(SendRequest).Return(httpResponse, nil)

		// create app rule facade
		appRuleFacade := &AppRuleFacade{
			restClient:    &restClientMock,
			appInstanceId: AppInstanceId,
		}

		response, _ := appRuleFacade.handleAppRuleRequest()

		// verify response
		assert.Equal(t, response.code, 200)
		assert.Equal(t, response.progressModel.ConfigResult, Success)
	})

	t.Run("TestAppRulePostFailure", func(t *testing.T) {
		httpResponse := &http.Response{
			StatusCode: 200,
			Body:       ioutil.NopCloser(bytes.NewBufferString(FailureResponse)),
		}

		// mock rest client
		restClientMock := RestClientMock{}
		restClientMock.On(SendRequest).Return(httpResponse, nil)

		// create app rule facade
		appRuleFacade := &AppRuleFacade{
			restClient:    &restClientMock,
			appInstanceId: AppInstanceId,
		}

		response, _ := appRuleFacade.handleAppRuleRequest()

		// verify response
		assert.Equal(t, response.code, 500)
		assert.Equal(t, response.progressModel.ConfigResult, Failure)
	})

	t.Run("TestTaskQueryFailureModel", func(t *testing.T) {
		httpResponse := &http.Response{
			StatusCode: 400,
			Body:       ioutil.NopCloser(bytes.NewBufferString(MepFailureResponse)),
		}

		// mock rest client
		restClientMock := RestClientMock{}
		restClientMock.On(SendRequest).Return(httpResponse, nil)

		// create app rule facade
		appRuleFacade := &AppRuleFacade{
			restClient:    &restClientMock,
			appInstanceId: AppInstanceId,
		}

		response, _ := appRuleFacade.handleAppRuleRequest()
		assert.Equal(t, response.code, 400)
		assert.Equal(t, response.progressModel.ConfigResult, Failure)
		assert.Equal(t, response.progressModel.Detailed, "duplicate entry")
	})

	t.Run("TestAppRuleConfigInProgress", func(t *testing.T) {
		httpResponse := &http.Response{
			StatusCode: 200,
			Body:       ioutil.NopCloser(bytes.NewBufferString(InProgressResponse)),
		}

		// mock rest client
		restClientMock := RestClientMock{}
		restClientMock.On(SendRequest).Return(httpResponse, nil)

		// create app rule facade
		appRuleFacade := &AppRuleFacade{
			restClient:    &restClientMock,
			appInstanceId: AppInstanceId,
		}

		_, err := appRuleFacade.handleAppRuleRequest()
		assert.Error(t, err)
	})

	t.Run("TestAppRuleConfigGetRequest", func(t *testing.T) {
		httpResponse := &http.Response{
			StatusCode: 200,
			Body:       ioutil.NopCloser(bytes.NewBufferString(AppRule)),
		}

		// mock rest client
		restClientMock := RestClientMock{}
		restClientMock.On(SendRequest).Return(httpResponse, nil)

		// create app rule facade
		appRuleFacade := &AppRuleFacade{
			restClient:    &restClientMock,
			appInstanceId: AppInstanceId,
		}

		response, _ := appRuleFacade.handleAppRuleGetRequest()
		assert.Equal(t, response.code, 200)
	})

	t.Run("TestAppRuleGetFailureModel", func(t *testing.T) {
		httpResponse := &http.Response{
			StatusCode: 404,
			Body:       ioutil.NopCloser(bytes.NewBufferString(NotFoundResponse)),
		}

		// mock rest client
		restClientMock := RestClientMock{}
		restClientMock.On(SendRequest).Return(httpResponse, nil)

		// create app rule facade
		appRuleFacade := &AppRuleFacade{
			restClient:    &restClientMock,
			appInstanceId: AppInstanceId,
		}

		response, _ := appRuleFacade.handleAppRuleGetRequest()
		assert.Equal(t, response.code, 404)
		assert.Equal(t, response.progressModel.ConfigResult, Failure)
		assert.Equal(t, response.progressModel.Detailed, "not found")
	})

	t.Run("TestCreateAppRuleFacade", func(t *testing.T) {
		restClient, _ := createRestClient(util.CreateAppdRuleUrl(AppInstanceId), util.Get, nil)
		appRuleFacade := createAppRuleFacade(restClient, AppInstanceId)
		assert.Equal(t, appRuleFacade.appInstanceId, AppInstanceId)
	})

	t.Run("TestCreateRestClientForPostRequest", func(t *testing.T) {
		appdModelBytes := []byte(AppRule)
		var rule *models.AppdRule
		_ = json.Unmarshal(appdModelBytes, &rule)
		restClient, _ := createRestClient(util.CreateAppdRuleUrl(AppInstanceId),
			util.Post, rule)
		assert.Equal(t, restClient.method, util.Post)
	})

	t.Run("TestCreateRestClientForPutRequest", func(t *testing.T) {
		appdModelBytes := []byte(AppRule)
		var rule *models.AppdRule
		_ = json.Unmarshal(appdModelBytes, &rule)
		restClient, _ := createRestClient(util.CreateAppdRuleUrl(AppInstanceId),
			util.Put, rule)
		assert.Equal(t, restClient.method, util.Put)
	})

	t.Run("TestCreateRestClientForDeleteRequest", func(t *testing.T) {
		restClient, _ := createRestClient(util.CreateAppdRuleUrl(AppInstanceId),
			util.Delete, nil)
		assert.Equal(t, restClient.method, util.Delete)
	})

	t.Run("TestCreateRestClientForUnknownMethod", func(t *testing.T) {
		_, err := createRestClient(util.CreateAppdRuleUrl(AppInstanceId),
			"unknown", nil)
		assert.Error(t, err)
	})

	t.Run("TestRatelimiter", func(t *testing.T) {
		r := &util.RateLimiter{}
		rate, _ := limiter.NewRateFromFormatted("200-S")
		r.GeneralLimiter = limiter.New(memory.NewStore(), rate)
		req, _ := http.NewRequest("GET",
			"https://127.0.0.1:8096/apprulemgr/v1/tenants/e921ce54-82c8-4532-b5c6-8516cf75f7a7/" +
			"app_instances/appd_configuration/sync_updated", bytes.NewBuffer([]byte("")))
		req.Header.Set("Content-Type", "application/json")
		controller := &AppRuleController{Controller :beego.Controller{Ctx: &context.Context{Request: req,
			ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}}}, Db: &PgDb{}}
		util.RateLimit(r, controller.Ctx)
		assert.Equal(t, 0, controller.Ctx.ResponseWriter.Status, "Test Ratelimit is passed")
	})
}
