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
	"errors"
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
	c.handleAppRuleConfig(util.Post)
}

// Updates app rule configuration
func (c *AppRuleController) UpdateAppRuleConfig() {
	log.Info("Application Rule Config update request received.")
	c.handleAppRuleConfig(util.Put)
}

// Deletes app rule configuration
func (c *AppRuleController) DeleteAppRuleConfig() {
	log.Info("Application Rule Config delete request received.")
	code, err := c.validateRequest([]string{util.MecmTenantRole, util.MecmAdminRole})
	if err != nil {
		c.handleLoggingForError(code, err.Error(), "")
		return
	}

	appInstanceId := c.Ctx.Input.Param(util.AppInstanceId)
	restClient, err := createRestClient(util.CreateAppdRuleUrl(appInstanceId), util.Delete, nil)
	if err != nil {
		c.handleLoggingForError(util.InternalServerError, err.Error(), appInstanceId)
		return
	}

	appRuleFacade := createAppRuleFacade(restClient, appInstanceId)
	response, err := appRuleFacade.handleAppRuleRequest()
	if err != nil {
		c.handleLoggingForError(util.InternalServerError, err.Error(), appInstanceId)
		return
	}

	progressModelBytes, err := json.Marshal(response.progressModel)
	if err != nil {
		c.handleLoggingForError(util.InternalServerError, util.MarshalProgressModelError, appInstanceId)
		return
	}
	c.writeResponse(progressModelBytes, response.code)
}

// Returns app rule configuration
func (c *AppRuleController) GetAppRuleConfig() {
	log.Info("Application Rule Config get request received.")
	code, err := c.validateRequest([]string{util.MecmTenantRole, util.MecmAdminRole, util.MecmGuestRole})
	if err != nil {
		c.handleLoggingForError(code, err.Error(), "")
		return
	}

	appInstanceId := c.Ctx.Input.Param(util.AppInstanceId)
	restClient, err := createRestClient(util.CreateAppdRuleUrl(appInstanceId), util.Get, nil)
	if err != nil {
		c.handleLoggingForError(util.InternalServerError, err.Error(), appInstanceId)
		return
	}

	appRuleFacade := createAppRuleFacade(restClient, appInstanceId)
	response, err := appRuleFacade.handleAppRuleGetRequest()
	if err != nil {
		c.handleLoggingForError(util.InternalServerError, err.Error(), appInstanceId)
		return
	}

	if response.code == http.StatusOK {
		appRuleModelBytes, err := json.Marshal(response.appdrule)
		if err != nil {
			c.handleLoggingForError(util.InternalServerError, util.MarshalAppRuleModelError, appInstanceId)
			return
		}
		c.writeResponse(appRuleModelBytes, response.code)
		return
	}

	progressModelBytes, err := json.Marshal(response.progressModel)
	if err != nil {
		c.handleLoggingForError(util.InternalServerError, util.MarshalProgressModelError, appInstanceId)
		return
	}
	c.writeResponse(progressModelBytes, response.code)
}

// Handled logging for error case
func (c *AppRuleController) handleLoggingForError(code int, errMsg string, appInstanceId string) {
	c.writeErrorResponse(errMsg, code, appInstanceId)
	clientIp := c.Ctx.Input.IP()
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

// validates api param
func (c *AppRuleController) validateApiParams() error {
	appInstanceId := c.Ctx.Input.Param(util.AppInstanceId)
	err := util.ValidateUUID(appInstanceId)
	if err != nil {
		return errors.New(util.AppInstanceIdInvalid)
	}

	tenantId := c.Ctx.Input.Param(util.TenantId)
	err = util.ValidateUUID(tenantId)
	if err != nil {
		return errors.New(util.TenantIdInvalid)
	}
	return nil
}

// validates and returns apprule model
func (c *AppRuleController) validateAppRuleModel() (*models.AppdRule, error) {
	if len(c.Ctx.Input.RequestBody) > util.RequestBodyLength {
		return nil, errors.New(util.RequestBodyTooLarge)
	}
	var appRuleConfig *models.AppdRule
	if err := json.Unmarshal(c.Ctx.Input.RequestBody, &appRuleConfig); err != nil {
		return nil, errors.New(util.UnMarshalAppRuleModelError)
	}

	err := util.ValidateRestBody(appRuleConfig)
	if err != nil {
		return nil, err
	}

	return appRuleConfig, nil
}

// validates rest request
func (c *AppRuleController) validateRequest(allowedRoles []string) (int, error) {
	clientIp := c.Ctx.Input.IP()
	err := util.ValidateIpv4Address(clientIp)
	if err != nil {
		return util.BadRequest, errors.New(util.ClientIpaddressInvalid)
	}
	c.displayReceivedMsg(clientIp)

	accessToken := c.Ctx.Request.Header.Get(util.AccessToken)
	tenantId := c.Ctx.Input.Param(util.TenantId)
	err = util.ValidateAccessToken(accessToken, allowedRoles, tenantId)
	if err != nil {
		if err.Error() == util.Forbidden {
			return util.StatusForbidden, errors.New(util.Forbidden)
		} else {
			return util.StatusUnauthorized, errors.New(util.AuthorizationFailed)
		}
	}
	bKey := *(*[]byte)(unsafe.Pointer(&accessToken))
	util.ClearByteArray(bKey)

	err = c.validateApiParams()
	if err != nil {
		return util.BadRequest, err
	}
	return 0, nil
}

func (c *AppRuleController) handleAppRuleConfig(method string) {
	code, err := c.validateRequest([]string{util.MecmTenantRole, util.MecmAdminRole})
	if err != nil {
		c.handleLoggingForError(code, err.Error(), "")
		return
	}

	appInstanceId := c.Ctx.Input.Param(util.AppInstanceId)
	appRuleConfig, err := c.validateAppRuleModel()
	if err != nil {
		c.handleLoggingForError(util.BadRequest, err.Error(), appInstanceId)
		return
	}

	restClient, err := createRestClient(util.CreateAppdRuleUrl(appInstanceId), method, appRuleConfig)
	if err != nil {
		c.handleLoggingForError(util.InternalServerError, err.Error(), appInstanceId)
		return
	}

	appRuleFacade := createAppRuleFacade(restClient, appInstanceId)
	response, err := appRuleFacade.handleAppRuleRequest()
	if err != nil {
		c.handleLoggingForError(util.InternalServerError, err.Error(), appInstanceId)
		return
	}

	progressModelBytes, err := json.Marshal(response.progressModel)
	if err != nil {
		c.handleLoggingForError(util.InternalServerError, util.MarshalProgressModelError, appInstanceId)
		return
	}
	c.writeResponse(progressModelBytes, response.code)
}
