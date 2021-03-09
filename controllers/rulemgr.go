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

const (
	AppdRule                        = "appd_rule"
	appdRuleId                      = "appd_rule_id"
	failedToMarshal          string = "failed to marshal request"
	lastInsertIdNotSupported string = "LastInsertId is not supported by this driver"
)

// Application Rule Controller
type AppRuleController struct {
	beego.Controller
	Db Database
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
	code, err := c.validateRequest([]string{util.MecmTenantRole, util.MecmAdminRole}, true)
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

	if response.code == http.StatusOK {
		tenantId := c.Ctx.Input.Param(util.TenantId)
		err = c.Db.DeleteData(tenantId+appInstanceId, appdRuleId)
		if err != nil {
			c.handleLoggingForError(util.InternalServerError, "Failed to delete app rule record for id"+
				tenantId+appInstanceId+"to database.", appInstanceId)
			return
		}
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
	code, err := c.validateRequest([]string{util.MecmTenantRole, util.MecmAdminRole, util.MecmGuestRole}, true)
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
func (c *AppRuleController) validateRequest(allowedRoles []string, isAppInstanceAvailable bool) (int, error) {
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
	code, err := c.validateRequest([]string{util.MecmTenantRole, util.MecmAdminRole}, true)
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

	// Add all UUID
	tenantId := c.Ctx.Input.Param(util.TenantId)
	appRuleConfig.AppdRuleId = tenantId + appInstanceId
	appRuleConfig.SyncStatus = false
	for _, apprule := range appRuleConfig.AppTrafficRule {
		for _, filter := range apprule.AppTrafficFilter {
			filter.TrafficFilterId = util.GenerateUniqueId()
		}
		for _, dstInterface := range apprule.DstInterface {
			dstInterface.DstInterfaceId = util.GenerateUniqueId()
			dstInterface.TunnelInfo.TunnelInfoId = util.GenerateUniqueId()
		}
	}

	if response.code == http.StatusOK {
		err = c.Db.InsertOrUpdateData(appRuleConfig, appdRuleId)
		if err != nil && err.Error() != "LastInsertId is not supported by this driver" {
			c.handleLoggingForError(util.InternalServerError, "Failed to save app info record for id"+
				appRuleConfig.AppdRuleId+"to database.", appInstanceId)
			return
		}
	}

	progressModelBytes, err := json.Marshal(response.progressModel)
	if err != nil {
		c.handleLoggingForError(util.InternalServerError, util.MarshalProgressModelError, appInstanceId)
		return
	}
	c.writeResponse(progressModelBytes, response.code)
}

// Synchronize added or update records
func (c *AppRuleController) SynchronizeUpdatedRecords() {
	log.Info("Sync app config request received.")

	var appdRules []*models.AppdRule
	var appdRulesSync []*models.AppdRule

	clientIp := c.Ctx.Input.IP()

	code, err := c.validateRequest([]string{util.MecmTenantRole, util.MecmAdminRole}, false)
	if err != nil {
		c.handleLoggingForSyncError(clientIp, code, err.Error())
		return
	}

	_, _ = c.Db.QueryTable(AppdRule).All(&appdRules)
	for _, appdRule := range appdRules {
		_, _ = c.Db.LoadRelated(appdRule, "AppTrafficRule")
		_, _ = c.Db.LoadRelated(appdRule, "AppDnsRule")
		for _, trafficRule := range appdRule.AppTrafficRule {
			_, _ = c.Db.LoadRelated(trafficRule, "AppTrafficFilter")
			_, _ = c.Db.LoadRelated(trafficRule, "DstInterface")
			for _, dstInterface := range trafficRule.DstInterface {
				_, _ = c.Db.LoadRelated(dstInterface, "TunnelInfo")
			}
		}
		if !appdRule.SyncStatus {
			appdRulesSync = append(appdRulesSync, appdRule)
		}
	}

	appRuleModelBytes, err := json.Marshal(appdRulesSync)
	if err != nil {
		c.writeSyncErrorResponse(failedToMarshal, util.BadRequest)
		return
	}

	c.writeResponse(appRuleModelBytes, http.StatusOK)

	for _, appdRule := range appdRulesSync {
		appdRule.SyncStatus = true
		err = c.Db.InsertOrUpdateData(appdRule, appdRuleId)
		if err != nil && err.Error() != lastInsertIdNotSupported {
			log.Error("Failed to save app rule record to database.")
			return
		}
	}
}

// Write error response
func (c *AppRuleController) writeSyncErrorResponse(errMsg string, code int) {
	log.Error(errMsg)
	c.writeSyncResponse(errMsg, code)
}

// Write response
func (c *AppRuleController) writeSyncResponse(msg string, code int) {
	c.Data["json"] = msg
	c.Ctx.ResponseWriter.WriteHeader(code)
	c.ServeJSON()
}

// Handled logging for error case
func (c *AppRuleController) handleLoggingForSyncError(clientIp string, code int, errMsg string) {
	c.writeSyncErrorResponse(errMsg, code)
	log.Info("Response message for ClientIP [" + clientIp + "] Operation [" + c.Ctx.Request.Method + "]" +
		" Resource [" + c.Ctx.Input.URL() + "] Result [Failure: " + errMsg + ".]")
}
