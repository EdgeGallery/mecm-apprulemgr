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
	"encoding/json"
	"github.com/astaxie/beego"
	log "github.com/sirupsen/logrus"
	"mecm-apprulemgr/models"
	"mecm-apprulemgr/util"
	"net/http"
	"unsafe"
)

// Application Rule Controller
type AppRuleController struct {
	beego.Controller
}

// Heath Check
func (c *AppRuleController) HealthCheck() {
	_, _ = c.Ctx.ResponseWriter.Write([]byte("ok"))
}

// Configures app rule
func (c *AppRuleController) CreateAppRuleConfig() {
	log.Info("Application Rule Config create request received.")

	clientIp := c.Ctx.Input.IP()
	err := util.ValidateIpv4Address(clientIp)
	if err != nil {
		c.handleLoggingForError(clientIp, util.BadRequest, util.ClientIpaddressInvalid, "")
		return
	}
	c.displayReceivedMsg(clientIp)

	accessToken := c.Ctx.Request.Header.Get(util.AccessToken)
	err = util.ValidateAccessToken(accessToken, []string{util.MecmTenantRole})
	if err != nil {
		c.handleLoggingForError(clientIp, util.StatusUnauthorized, util.AuthorizationFailed, "")
		return
	}
	bKey := *(*[]byte)(unsafe.Pointer(&accessToken))
	util.ClearByteArray(bKey)

	appInstanceId := c.Ctx.Input.Param(util.AppInstanceId)
	err = util.ValidateUUID(appInstanceId)
	if err != nil {
		c.handleLoggingForError(clientIp, util.BadRequest, util.AppInstanceId, appInstanceId)
		return
	}

	tenantId := c.Ctx.Input.Param(util.TenantId)
	err = util.ValidateUUID(tenantId)
	if err != nil {
		c.handleLoggingForError(clientIp, util.BadRequest, util.TenantIdInvalid, appInstanceId)
		return
	}

	var appRuleConfig *models.AppdRule
	if err = json.Unmarshal(c.Ctx.Input.RequestBody, &appRuleConfig); err != nil {
		c.handleLoggingForError(clientIp, util.BadRequest, err.Error(), appInstanceId)
		return
	}

	restClient, err := createRestClient(util.CreateAppdRuleUrl(appInstanceId), util.Post, appRuleConfig)
	if err != nil {
		c.handleLoggingForError(clientIp, util.InternalServerError, err.Error(), appInstanceId)
		return
	}

	appRuleFacade := createAppRuleFacade(restClient, appInstanceId)
	response, err := appRuleFacade.handleAppRuleRequest()
	if err != nil {
		c.handleLoggingForError(clientIp, util.InternalServerError, err.Error(), appInstanceId)
		return
	}

	progressModelBytes, err := json.Marshal(response.progressModel)
	if err != nil {
		c.handleLoggingForError(clientIp, util.InternalServerError, util.MarshalProgressModelError, appInstanceId)
		return
	}
	c.writeResponse(progressModelBytes, response.code)
}

// Updates app rule configuration
func (c *AppRuleController) UpdateAppRuleConfig() {
	log.Info("Application Rule Config update request received.")

	clientIp := c.Ctx.Input.IP()
	err := util.ValidateIpv4Address(clientIp)
	if err != nil {
		c.handleLoggingForError(clientIp, util.BadRequest, util.ClientIpaddressInvalid, "")
		return
	}
	c.displayReceivedMsg(clientIp)

	accessToken := c.Ctx.Request.Header.Get(util.AccessToken)
	err = util.ValidateAccessToken(accessToken, []string{util.MecmTenantRole})
	if err != nil {
		c.handleLoggingForError(clientIp, util.StatusUnauthorized, util.AuthorizationFailed, "")
		return
	}
	bKey := *(*[]byte)(unsafe.Pointer(&accessToken))
	util.ClearByteArray(bKey)

	appInstanceId := c.Ctx.Input.Param(util.AppInstanceId)
	err = util.ValidateUUID(appInstanceId)
	if err != nil {
		c.handleLoggingForError(clientIp, util.BadRequest, util.AppInstanceId, appInstanceId)
		return
	}

	tenantId := c.Ctx.Input.Param(util.TenantId)
	err = util.ValidateUUID(tenantId)
	if err != nil {
		c.handleLoggingForError(clientIp, util.BadRequest, util.TenantIdInvalid, appInstanceId)
		return
	}

	var appRuleConfig *models.AppdRule
	if err = json.Unmarshal(c.Ctx.Input.RequestBody, &appRuleConfig); err != nil {
		c.handleLoggingForError(clientIp, util.BadRequest, err.Error(), appInstanceId)
		return
	}

	restClient, err := createRestClient(util.CreateAppdRuleUrl(appInstanceId), util.Put, appRuleConfig)
	if err != nil {
		c.handleLoggingForError(clientIp, util.InternalServerError, err.Error(), appInstanceId)
		return
	}

	appRuleFacade := createAppRuleFacade(restClient, appInstanceId)
	response, err := appRuleFacade.handleAppRuleRequest()
	if err != nil {
		c.handleLoggingForError(clientIp, util.InternalServerError, err.Error(), appInstanceId)
		return
	}

	progressModelBytes, err := json.Marshal(response.progressModel)
	if err != nil {
		c.handleLoggingForError(clientIp, util.InternalServerError, util.MarshalProgressModelError, appInstanceId)
		return
	}
	c.writeResponse(progressModelBytes, response.code)
}

// Deletes app rule configuration
func (c *AppRuleController) DeleteAppRuleConfig() {
	log.Info("Application Rule Config delete request received.")

	clientIp := c.Ctx.Input.IP()
	err := util.ValidateIpv4Address(clientIp)
	if err != nil {
		c.handleLoggingForError(clientIp, util.BadRequest, util.ClientIpaddressInvalid, "")
		return
	}
	c.displayReceivedMsg(clientIp)

	accessToken := c.Ctx.Request.Header.Get(util.AccessToken)
	err = util.ValidateAccessToken(accessToken, []string{util.MecmTenantRole})
	if err != nil {
		c.handleLoggingForError(clientIp, util.StatusUnauthorized, util.AuthorizationFailed, "")
		return
	}
	bKey := *(*[]byte)(unsafe.Pointer(&accessToken))
	util.ClearByteArray(bKey)

	appInstanceId := c.Ctx.Input.Param(util.AppInstanceId)
	err = util.ValidateUUID(appInstanceId)
	if err != nil {
		c.handleLoggingForError(clientIp, util.BadRequest, util.AppInstanceId, appInstanceId)
		return
	}

	tenantId := c.Ctx.Input.Param(util.TenantId)
	err = util.ValidateUUID(tenantId)
	if err != nil {
		c.handleLoggingForError(clientIp, util.BadRequest, util.TenantIdInvalid, appInstanceId)
		return
	}

	restClient, err := createRestClient(util.CreateAppdRuleUrl(appInstanceId), util.Delete, nil)
	if err != nil {
		c.handleLoggingForError(clientIp, util.InternalServerError, err.Error(), appInstanceId)
		return
	}

	appRuleFacade := createAppRuleFacade(restClient, appInstanceId)
	response, err := appRuleFacade.handleAppRuleRequest()
	if err != nil {
		c.handleLoggingForError(clientIp, util.InternalServerError, err.Error(), appInstanceId)
		return
	}

	progressModelBytes, err := json.Marshal(response.progressModel)
	if err != nil {
		c.handleLoggingForError(clientIp, util.InternalServerError, util.MarshalProgressModelError, appInstanceId)
		return
	}
	c.writeResponse(progressModelBytes, response.code)
}

// Returns app rule configuration
func (c *AppRuleController) GetAppRuleConfig() {
	log.Info("Application Rule Config get request received.")

	clientIp := c.Ctx.Input.IP()
	err := util.ValidateIpv4Address(clientIp)
	if err != nil {
		c.handleLoggingForError(clientIp, util.BadRequest, util.ClientIpaddressInvalid, "")
		return
	}
	c.displayReceivedMsg(clientIp)

	accessToken := c.Ctx.Request.Header.Get(util.AccessToken)
	err = util.ValidateAccessToken(accessToken, []string{util.MecmTenantRole})
	if err != nil {
		c.handleLoggingForError(clientIp, util.StatusUnauthorized, util.AuthorizationFailed, "")
		return
	}
	bKey := *(*[]byte)(unsafe.Pointer(&accessToken))
	util.ClearByteArray(bKey)

	appInstanceId := c.Ctx.Input.Param(util.AppInstanceId)
	err = util.ValidateUUID(appInstanceId)
	if err != nil {
		c.handleLoggingForError(clientIp, util.BadRequest, util.AppInstanceId, appInstanceId)
		return
	}

	tenantId := c.Ctx.Input.Param(util.TenantId)
	err = util.ValidateUUID(tenantId)
	if err != nil {
		c.handleLoggingForError(clientIp, util.BadRequest, util.TenantIdInvalid, appInstanceId)
		return
	}

	restClient, err := createRestClient(util.CreateAppdRuleUrl(appInstanceId), util.Get, nil)
	if err != nil {
		c.handleLoggingForError(clientIp, util.InternalServerError, err.Error(), appInstanceId)
		return
	}

	appRuleFacade := createAppRuleFacade(restClient, appInstanceId)
	response, err := appRuleFacade.handleAppRuleGetRequest()
	if err != nil {
		c.handleLoggingForError(clientIp, util.InternalServerError, err.Error(), appInstanceId)
		return
	}

	if response.code == http.StatusOK {
		appRuleModelBytes, err := json.Marshal(response.appdrule)
		if err != nil {
			c.handleLoggingForError(clientIp, util.InternalServerError, util.MarshalAppRuleModelError, appInstanceId)
			return
		}
		c.writeResponse(appRuleModelBytes, response.code)
		return
	}

	progressModelBytes, err := json.Marshal(response.progressModel)
	if err != nil {
		c.handleLoggingForError(clientIp, util.InternalServerError, util.MarshalProgressModelError, appInstanceId)
		return
	}
	c.writeResponse(progressModelBytes, response.code)
}

// Handled logging for error case
func (c *AppRuleController) handleLoggingForError(clientIp string, code int, errMsg string, appInstanceId string) {
	c.writeErrorResponse(errMsg, code, appInstanceId)
	log.Info("Response message for ClientIP [" + clientIp + "] Operation [" + c.Ctx.Request.Method + "]" +
		" Resource [" + c.Ctx.Input.URL() + "] Result [Failure: " + errMsg + ".]")
}

// Write error response
func (c *AppRuleController) writeErrorResponse(errMsg string, code int, appInstanceId string) {
	progressModel := util.CreateOperationProgressModel(appInstanceId, util.Failure, errMsg)
	progressModelBytes, err := json.Marshal(progressModel)
	if err != nil {
		log.Error(util.MarshalProgressModelError)
		return
	}
	log.Error(errMsg)
	c.writeResponse(progressModelBytes, code)
}

// Write response
func (c *AppRuleController) writeResponse(msg []byte, code int) {
	c.Ctx.Output.SetStatus(code)
	err := c.Ctx.Output.Body(msg)
	if err != nil {
		log.Error(util.FailedToWriteRes)
	}
}

// To display log for received message
func (c *AppRuleController) displayReceivedMsg(clientIp string) {
	log.Info("Received message from ClientIP [" + clientIp + "] Operation [" + c.Ctx.Request.Method + "]" +
		" Resource [" + c.Ctx.Input.URL() + "]")
}
