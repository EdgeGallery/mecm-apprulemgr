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

package main

import (
	"bytes"
	"github.com/astaxie/beego"
	"github.com/astaxie/beego/context"
	"github.com/dgrijalva/jwt-go"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"mecm-apprulemgr/controllers"
	"mecm-apprulemgr/util"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/agiledragon/gomonkey"
)

var (
	fwdIp = "1.1.1.1:10000"
)

const (
	baseUrl       string = "https://edgegallery:8096/apprulemgr/v1/"
	tenantId      string = "94d6e70d-51f7-4b0d-965f-59dca2c3002c"
	appInstanceId string = "71ea862b-5806-4196-bce3-434bf9c95b18"
	appRule       string = "{\n\"appdRuleId\":" +
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
	progressModel = "{\"taskId\":\"51ea862b-5806-4196-bce3-434bf9c95b18\"," +
		"\"appInstanceId\":\"71ea862b-5806-4196-bce3-434bf9c95b18\"," +
		"\"configResult\":\"SUCCESS\",\"configPhase\":\"0\",\"detailed\":\"success\"}"
	ParamTenantId      = ":tenantId"
	ParamAppInstanceId = ":appInstanceId"
	userId             = tenantId
	Post               = "POST"
	Put                = "PUT"
	Get                = "GET"
	Delete             = "DELETE"
)

// Creates http request
func getHttpRequest(uri string, method string, body []byte) (req *http.Request, err error) {
	req, err = http.NewRequest(method, uri, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	accessToken := createToken(userId)
	// Add additional headers
	req.Header.Set("access_token", accessToken)
	req.Header.Set("X-Forwarded-For", fwdIp)
	return req, nil
}

func setParam(ctx *context.BeegoInput, params map[string]string) {
	for key, val := range params {
		ctx.SetParam(key, val)
	}
}

func createAppRuleConfigUrl(tenantId string, appInstanceId string) string {
	return baseUrl + "tenants/" + tenantId +
		"/app_instances/" + appInstanceId + "/appd_configuration"
}

func createToken(userid string) string {
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

func setup(method string, body []byte, appInstanceId string, tenantId string) *controllers.AppRuleController {
	request, _ := getHttpRequest(createAppRuleConfigUrl(tenantId, appInstanceId), method, body)
	extraParams := map[string]string{
		ParamTenantId:      tenantId,
		ParamAppInstanceId: appInstanceId,
	}
	// Prepare Input
	input := &context.BeegoInput{Context: &context.Context{Request: request}, RequestBody: []byte(appRule)}
	setParam(input, extraParams)

	output := &context.BeegoOutput{Context: &context.Context{ResponseWriter: &context.
	Response{ResponseWriter: httptest.NewRecorder()}}}

	// Prepare beego controller
	appRuleBeegoController := beego.Controller{Ctx: &context.Context{Input: input, Output: output,
		Request: request, ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
		Data: make(map[interface{}]interface{})}

	// Create app rule controller with prepared beego controller
	return &controllers.AppRuleController{Controller: appRuleBeegoController, Db:&controllers.MockDb{}}
}

func TestGetAppRuleConfig(t *testing.T) {
	// Mock the required API
	patch2 := gomonkey.ApplyFunc(util.ClearByteArray, func(_ []byte) {
		// do nothing
	})
	defer patch2.Reset()

	patch4 := gomonkey.ApplyFunc(util.DoRequest, func(_ *http.Request) (*http.Response, error) {
		// do nothing
		return &http.Response{
			Body:       ioutil.NopCloser(bytes.NewBufferString(appRule)),
			StatusCode: 200,
			Status:     "200",
		}, nil
	})
	defer patch4.Reset()

	appRuleController := setup(Get, nil, appInstanceId, tenantId)
	// Test Capability
	appRuleController.GetAppRuleConfig()

	// Check for success case wherein the status value will be default i.e. 0
	assert.Equal(t, 200, appRuleController.Ctx.Output.Context.ResponseWriter.Status)
}

func TestAppRuleConfigRequest(t *testing.T) {
	// Mock the required API
	patch2 := gomonkey.ApplyFunc(util.ClearByteArray, func(_ []byte) {
		// do nothing
	})
	defer patch2.Reset()

	patch4 := gomonkey.ApplyFunc(util.DoRequest, func(_ *http.Request) (*http.Response, error) {
		// do nothing
		return &http.Response{
			Body:       ioutil.NopCloser(bytes.NewBufferString(progressModel)),
			StatusCode: 200,
			Status:     "200",
		}, nil
	})
	defer patch4.Reset()

	t.Run("TestPostAppRuleConfig", func(t *testing.T) {
		appRuleController := setup(Post, []byte(appRule), appInstanceId, tenantId)

		// Test Capability
		appRuleController.CreateAppRuleConfig()

		// Check for success case wherein the status value will be default i.e. 0
		assert.Equal(t, 200, appRuleController.Ctx.Output.Context.ResponseWriter.Status)
	})

	t.Run("TestPutAppRuleConfig", func(t *testing.T) {
		appRuleController := setup(Put, []byte(appRule), appInstanceId, tenantId)

		// Test Capability
		appRuleController.UpdateAppRuleConfig()

		// Check for success case wherein the status value will be default i.e. 0
		assert.Equal(t, 200, appRuleController.Ctx.Output.Context.ResponseWriter.Status)
		response := appRuleController.Ctx.Output.Context.ResponseWriter.ResponseWriter.(*httptest.ResponseRecorder)
		assert.Equal(t, len(progressModel), len(response.Body.String()))
	})

	t.Run("TestDeleteAppRuleConfig", func(t *testing.T) {
		appRuleController := setup(Delete, nil, appInstanceId, tenantId)

		// Test Capability
		appRuleController.DeleteAppRuleConfig()

		// Check for success case wherein the status value will be default i.e. 0
		assert.Equal(t, 200, appRuleController.Ctx.Output.Context.ResponseWriter.Status)
	})

	t.Run("TestInvalidAppInstanceId", func(t *testing.T) {
		appRuleController := setup(Delete, nil, "1234", tenantId)

		// Test Capability
		appRuleController.DeleteAppRuleConfig()

		// Check for success case wherein the status value will be default i.e. 0
		assert.Equal(t, 400, appRuleController.Ctx.Output.Context.ResponseWriter.Status)
	})
}
func TestSynchronizeUpdatedRecords(t *testing.T) {

	synchronizeUpdatedRecords := setup(Get, nil, appInstanceId, tenantId)
	// Test Capability
	synchronizeUpdatedRecords.SynchronizeUpdatedRecords()

	// Check for success case wherein the status value will be default i.e. 0
	assert.Equal(t, 0, synchronizeUpdatedRecords.Ctx.Output.Context.ResponseWriter.Status)
}

func TestSynchronizeDeletedRecords(t *testing.T) {

	synchronizeDeletedRecords := setup(Get, nil, appInstanceId, tenantId)
	// Test Capability
	synchronizeDeletedRecords.SynchronizeDeletedRecords()

	// Check for success case wherein the status value will be default i.e. 0
	assert.Equal(t, 0, synchronizeDeletedRecords.Ctx.Output.Context.ResponseWriter.Status)
}

func TestWriteSyncErrorResponse(t *testing.T) {

	writeSyncErrorResponse1 := setup(Get, nil, appInstanceId, tenantId)
	// Test Capability
	writeSyncErrorResponse1.WriteSyncErrorResponse("There is an error", 1)

}

func TestHandleLoggingForSyncError(t *testing.T) {

	handleLoggingForSyncError := setup(Get, nil, appInstanceId, tenantId)
	// Test Capability
	handleLoggingForSyncError.HandleLoggingForSyncError("256.1.1.1", 1, "error")

}
