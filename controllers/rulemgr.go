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
	"strings"
	"unsafe"
)

const (
	appdRule                        = "appd_rule_rec"
	appdRuleId                      = "appd_rule_id"
	failedToMarshal                 = "failed to marshal request"
	lastInsertIdNotSupported        = "LastInsertId is not supported by this driver"
	toDatabase                      = "to database."
	operation                       = "] Operation ["
	resource                        = " Resource ["
	applicationJson                 = "application/json"
)

// AppRuleController Application Rule Controller
type AppRuleController struct {
	beego.Controller
	Db Database
}

// HealthCheck information
func (c *AppRuleController) HealthCheck() {
	_, _ = c.Ctx.ResponseWriter.Write([]byte("ok"))
}

// CreateAppRuleConfig Configures app rule
func (c *AppRuleController) CreateAppRuleConfig() {
	log.Info("Application Rule Config create request received.")
	c.HandleAppRuleConfig(util.Post)
}

// UpdateAppRuleConfig Updates app rule configuration
func (c *AppRuleController) UpdateAppRuleConfig() {
	log.Info("Application Rule Config update request received.")
	c.HandleAppRuleConfig(util.Put)
}

// DeleteAppRuleConfig Deletes app rule configuration
func (c *AppRuleController) DeleteAppRuleConfig() {
	log.Info("Application Rule Config delete request received.")
	code, err := c.ValidateRequest([]string{util.MecmTenantRole, util.MecmAdminRole}, true)
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

	tenantId := c.Ctx.Input.Param(util.TenantId)
	appdRuleRecord := &models.AppdRuleRec{
		AppdRuleId: tenantId+appInstanceId,
	}
	if response.code == http.StatusOK {
		err = c.Db.DeleteData(appdRuleRecord, appdRuleId)
		if err != nil {
			c.handleLoggingForError(util.InternalServerError, "Failed to delete app rule record for id"+
				tenantId+appInstanceId+toDatabase, appInstanceId)
			return
		}
	}

	// Add stale record
	rule := &models.StaleAppdRule{AppdRuleId: tenantId + appInstanceId, TenantId: tenantId, AppInstanceId: appInstanceId}
	err = c.Db.InsertOrUpdateData(rule, appdRuleId)
	if err != nil && err.Error() != lastInsertIdNotSupported {
		c.handleLoggingForError(util.InternalServerError, "Failed to save app rule record for id"+
			rule.AppdRuleId+toDatabase, appInstanceId)
		return
	}

	progressModelBytes, err := json.Marshal(response.progressModel)
	if err != nil {
		c.handleLoggingForError(util.InternalServerError, util.MarshalProgressModelError, appInstanceId)
		return
	}
	c.WriteResponse(progressModelBytes, response.code)
}

// GetAppRuleConfig Returns app rule configuration
func (c *AppRuleController) GetAppRuleConfig() {
	log.Info("Application Rule Config get request received.")
	code, err := c.ValidateRequest([]string{util.MecmTenantRole, util.MecmAdminRole, util.MecmGuestRole}, true)
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
		c.WriteResponse(appRuleModelBytes, response.code)
		return
	}

	progressModelBytes, err := json.Marshal(response.progressModel)
	if err != nil {
		c.handleLoggingForError(util.InternalServerError, util.MarshalProgressModelError, appInstanceId)
		return
	}
	c.WriteResponse(progressModelBytes, response.code)
}

// Handled logging for error case
func (c *AppRuleController) handleLoggingForError(code int, errMsg string, appInstanceId string) {
	c.WriteErrorResponse(errMsg, code, appInstanceId)
	clientIp := c.Ctx.Input.IP()
	log.Info("Response message for ClientIP [" + clientIp + operation + c.Ctx.Request.Method + "]" +
		resource + c.Ctx.Input.URL() + "] Result [Failure: " + errMsg + ".]")
}

// Write error response
func (c *AppRuleController) WriteErrorResponse(errMsg string, code int, appInstanceId string) {
	progressModel := util.CreateOperationProgressModel(appInstanceId, util.Failure, errMsg)
	progressModelBytes, err := json.Marshal(progressModel)
	if err != nil {
		log.Error(util.MarshalProgressModelError)
		return
	}
	log.Error(errMsg)
	c.WriteResponse(progressModelBytes, code)
}

// Write response
func (c *AppRuleController) WriteResponse(msg []byte, code int) {
	c.Ctx.Output.SetStatus(code)
	err := c.Ctx.Output.Body(msg)
	if err != nil {
		log.Error(util.FailedToWriteRes)
	}
}

// To display log for received message
func (c *AppRuleController) displayReceivedMsg(clientIp string) {
	log.Info("Received message from ClientIP [" + clientIp + operation + c.Ctx.Request.Method + "]" +
		resource + c.Ctx.Input.URL() + "]")
}

// validates api param
func (c *AppRuleController) validateApiParams() error {
	appInstanceId := c.Ctx.Input.Param(util.AppInstanceId)
	if appInstanceId != "" {
		err := util.ValidateUUID(appInstanceId)
		if err != nil {
			return errors.New(util.AppInstanceIdInvalid)
		}
	}

	tenantId := c.Ctx.Input.Param(util.TenantId)
	err := util.ValidateUUID(tenantId)
	if err != nil {
		return errors.New(util.TenantIdInvalid)
	}
	return nil
}

// validates and returns apprule model
func (c *AppRuleController) ValidateAppRuleModel() (*models.AppdRule, error) {
	if len(c.Ctx.Input.RequestBody) > util.RequestBodyLength {
		return nil, errors.New(util.RequestBodyTooLarge)
	}
	var appRuleConfig *models.AppdRule
	if err := json.Unmarshal(c.Ctx.Input.RequestBody, &appRuleConfig); err != nil {
		log.Error("failed to unmarshal")
		return nil, errors.New(util.UnMarshalAppRuleModelError)
	}

	err := util.ValidateRestBody(appRuleConfig)
	if err != nil {
		log.Error("failed to validate rest body")
		return nil, err
	}

	return appRuleConfig, nil
}

// validates rest request
func (c *AppRuleController) ValidateRequest(allowedRoles []string, isAppInstanceAvailable bool) (int, error) {
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

// Handle app rule configuration
func (c *AppRuleController) HandleAppRuleConfig(method string) {
	code, err := c.ValidateRequest([]string{util.MecmTenantRole, util.MecmAdminRole}, true)
	if err != nil {
		c.handleLoggingForError(code, err.Error(), "")
		return
	}

	appInstanceId := c.Ctx.Input.Param(util.AppInstanceId)
	err = util.ValidateUUID(appInstanceId)
	if err != nil {
		c.handleLoggingForError(code, err.Error(), "")
		return
	}
	appRuleConfig, err := c.ValidateAppRuleModel()
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

	origin := c.Ctx.Request.Header.Get("origin")
	originVar, err := util.ValidateName(origin, util.NameRegex)
	if err != nil || !originVar {
		c.handleLoggingForError(util.BadRequest, err.Error(), appInstanceId)
		return
	}

	syncStatus := true
	if origin == "MEPM" {
		syncStatus = false
	}

	// Add all UUID
	tenantId := c.Ctx.Input.Param(util.TenantId)
	err = util.ValidateUUID(tenantId)
	if err != nil {
		c.handleLoggingForError(util.BadRequest, err.Error(), appInstanceId)
		return
	}

	appdRuleRecord := &models.AppdRuleRec{
		AppdRuleId: tenantId+appInstanceId,
	}

	_ = c.Db.DeleteData(appdRuleRecord, appdRuleId)

	appdRuleRec := &models.AppdRuleRec{
		AppdRuleId: tenantId + appInstanceId,
		TenantId: tenantId,
		AppInstanceId: appInstanceId,
		AppName:  appRuleConfig.AppName,
		AppSupportMp1: appRuleConfig.AppSupportMp1,
		SyncStatus: syncStatus,
		Origin     : origin,
	}

	err = c.Db.InsertOrUpdateData(appdRuleRec, "appd_rule_id")
	if err != nil && err.Error() != lastInsertIdNotSupported {
		c.handleLoggingForError(util.InternalServerError, "Failed to save appd rule record for id"+
			appdRuleRec.AppdRuleId+toDatabase, appInstanceId)
		return
	}

	err = c.InsertOrUpdateAppTrafficRuleRec(appRuleConfig, appdRuleRec, appInstanceId)
	if err != nil {
		log.Error("failed to insert app traffic rule record")
		return
	}

	err = c.insertOrUpdateAppDnsRuleRec(appRuleConfig, appdRuleRec, appInstanceId)
	if err != nil {
		log.Error("failed to insert dns rule record")
		return
	}

	progressModelBytes, err := json.Marshal(response.progressModel)
	if err != nil {
		c.handleLoggingForError(util.InternalServerError, util.MarshalProgressModelError, appInstanceId)
		return
	}
	c.WriteResponse(progressModelBytes, response.code)
}

// SynchronizeUpdatedRecords Synchronize added or update records
func (c *AppRuleController) SynchronizeUpdatedRecords() {
	log.Info("Sync app config request received.")

	var syncUpdatedRulesRecords models.SyncUpdatedRulesRecords

	clientIp := c.Ctx.Input.IP()

	code, err := c.ValidateRequest([]string{util.MecmTenantRole, util.MecmAdminRole}, false)
	if err != nil {
		c.HandleLoggingForSyncError(clientIp, code, err.Error())
		return
	}

	appdRulesSync := c.getAppdRuleSyncInfo()
	syncUpdatedRulesRecords.AppdRuleUpdatedRecs = append(syncUpdatedRulesRecords.AppdRuleUpdatedRecs, appdRulesSync...)
	syncUpdatedRulesRecs := c.GetSyncUpdatedRulesRecs(syncUpdatedRulesRecords)
	c.SendSyncUpdatedRulesRecs(syncUpdatedRulesRecs, appdRulesSync, clientIp)
}

// SynchronizeDeletedRecords Synchronize deleted records
func (c *AppRuleController) SynchronizeDeletedRecords() {
	log.Info("Sync deleted app rule records request received.")

	var staleRules []models.StaleAppdRule
	var syncDeletedRulesRecords models.SyncDeletedRulesRecords


	clientIp := c.Ctx.Input.IP()
	err := util.ValidateIpv4Address(clientIp)
	if err != nil {
		c.WriteSyncErrorResponse("invalid ip address", util.BadRequest)
		return
	}
	code, err := c.ValidateRequest([]string{util.MecmTenantRole, util.MecmAdminRole}, false)
	if err != nil {
		c.HandleLoggingForSyncError(clientIp, code, err.Error())
		return
	}
	_, _ = c.Db.QueryTable("stale_appd_rule", &staleRules, "tenant_id", c.Ctx.Input.Param(util.TenantId))
	syncDeletedRulesRecords.AppdRuleDeletedRecs = append(syncDeletedRulesRecords.AppdRuleDeletedRecs, staleRules...)
	appRuleModelBytes, err := json.Marshal(syncDeletedRulesRecords)
	if err != nil {
		c.WriteSyncErrorResponse(failedToMarshal, util.BadRequest)
		return
	}

	c.Ctx.ResponseWriter.Header().Set("Content-Type", applicationJson)
	c.Ctx.ResponseWriter.Header().Set("Accept", applicationJson)
	_, _ = c.Ctx.ResponseWriter.Write(appRuleModelBytes)
	for _, staleRule := range staleRules {
		err = c.Db.DeleteData(&staleRule, appdRuleId)
		if err != nil && err.Error() != lastInsertIdNotSupported {
			c.HandleLoggingForSyncError(clientIp, util.InternalServerError, "Failed to delete stale data in " +
				"database with error: ." + err.Error())
			return
		}
	}
}

// Write error response
func (c *AppRuleController) WriteSyncErrorResponse(errMsg string, code int) {
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
func (c *AppRuleController) HandleLoggingForSyncError(clientIp string, code int, errMsg string) {
	c.WriteSyncErrorResponse(errMsg, code)
	log.Info("Response message for ClientIP [" + clientIp + operation + c.Ctx.Request.Method + "]" +
		resource + c.Ctx.Input.URL() + "] Result [Failure: " + errMsg + ".]")
}

// Insert source address record
func (c *AppRuleController) InsertSrcAddressRec(filter models.TrafficFilter, trafficFilterRec *models.TrafficFilterRec,
	appInstanceId string) error {

	for _, srcAddress := range filter.SrcAddress {
		srcAddressRec := &models.SrcAddress{
			SrcAddress: srcAddress,
			TrafficFilterRec: trafficFilterRec,
		}
		err := c.Db.InsertOrUpdateData(srcAddressRec, "src_address")
		if err != nil && err.Error() != lastInsertIdNotSupported {
			c.handleLoggingForError(util.InternalServerError, "Failed to save src address record record for id"+
				filter.TrafficFilterId +toDatabase, appInstanceId)
			return err
		}
	}
	return nil
}

// Insert source port record
func (c *AppRuleController) insertSrcPortRec(filter models.TrafficFilter, trafficFilterRec *models.TrafficFilterRec,
	appInstanceId string) error {

	for _, srcPort := range filter.SrcPort {
		srcPortRec := &models.SrcPort{
			SrcPort: srcPort,
			TrafficFilterRec: trafficFilterRec,
		}
		err := c.Db.InsertOrUpdateData(srcPortRec, "src_port")
		if err != nil && err.Error() != lastInsertIdNotSupported {
			c.handleLoggingForError(util.InternalServerError, "Failed to save src port record record for id"+
				filter.TrafficFilterId +toDatabase, appInstanceId)
			return err
		}
	}
	return nil
}

// Insert destination address record
func (c *AppRuleController) insertDstAddressRec(filter models.TrafficFilter, trafficFilterRec *models.TrafficFilterRec,
	appInstanceId string) error {

	for _, dstAddress := range filter.DstAddress {
		dstAddressRec := &models.DstAddress{
			DstAddress: dstAddress,
			TrafficFilterRec: trafficFilterRec,
		}
		err := c.Db.InsertOrUpdateData(dstAddressRec, "dst_address")
		if err != nil && err.Error() != lastInsertIdNotSupported {
			c.handleLoggingForError(util.InternalServerError, "Failed to save dst address record record for id"+
				filter.TrafficFilterId +toDatabase, appInstanceId)
			return err
		}
	}
	return nil
}

// Insert destination port record
func (c *AppRuleController) insertDstPortRec(filter models.TrafficFilter, trafficFilterRec *models.TrafficFilterRec,
	appInstanceId string) error {

	for _, dstPort := range filter.DstPort {
		dstPortRec := &models.DstPort{
			DstPort: dstPort,
			TrafficFilterRec: trafficFilterRec,
		}
		err := c.Db.InsertOrUpdateData(dstPortRec, "dst_port")
		if err != nil && err.Error() != lastInsertIdNotSupported {
			c.handleLoggingForError(util.InternalServerError, "Failed to save dst port record record for id"+
				filter.TrafficFilterId +toDatabase, appInstanceId)
			return err
		}
	}
	return nil
}

// Insert protocol record
func (c *AppRuleController) insertProtocolRec(filter models.TrafficFilter, trafficFilterRec *models.TrafficFilterRec,
	appInstanceId string) error {

	for _, protocol := range filter.Protocol {
		protocolRec := &models.Protocol{
			Protocol: protocol,
			TrafficFilterRec: trafficFilterRec,
		}
		err := c.Db.InsertOrUpdateData(protocolRec, "protocol")
		if err != nil && err.Error() != lastInsertIdNotSupported {
			c.handleLoggingForError(util.InternalServerError, "Failed to save protocol record record for id"+
				filter.TrafficFilterId +toDatabase, appInstanceId)
			return err
		}
	}
	return nil
}

// Insert tag record
func (c *AppRuleController) insertTagRec(filter models.TrafficFilter, trafficFilterRec *models.TrafficFilterRec,
	appInstanceId string) error {

	for _, tag := range filter.Tag {
		tagRec := &models.Tag{
			Tag: tag,
			TrafficFilterRec: trafficFilterRec,
		}
		err := c.Db.InsertOrUpdateData(tagRec, "tag")
		if err != nil && err.Error() != lastInsertIdNotSupported {
			c.handleLoggingForError(util.InternalServerError, "Failed to save tag record record for id"+
				filter.TrafficFilterId +toDatabase, appInstanceId)
			return err
		}
	}
	return nil
}

// Insert source tunnel address record
func (c *AppRuleController) insertSrcTunnelAddressRec(filter models.TrafficFilter, trafficFilterRec *models.TrafficFilterRec,
	appInstanceId string) error {

	for _, srcTunnelAddr := range filter.SrcTunnelAddress {
		srcTunnelAddrRec := &models.SrcTunnelAddress{
			SrcTunnelAddress: srcTunnelAddr,
			TrafficFilterRec: trafficFilterRec,
		}
		err := c.Db.InsertOrUpdateData(srcTunnelAddrRec, "src_tunnel_address")
		if err != nil && err.Error() != lastInsertIdNotSupported {
			c.handleLoggingForError(util.InternalServerError, "Failed to save src tunnel address record record for id"+
				filter.TrafficFilterId +toDatabase, appInstanceId)
			return err
		}
	}
	return nil
}

// Insert destination tunnel address record
func (c *AppRuleController) insertDstTunnelAddressRec(filter models.TrafficFilter, trafficFilterRec *models.TrafficFilterRec,
	appInstanceId string) error {

	for _, dstTunnelAddress := range filter.DstTunnelAddress {
		dstTunnelAddressRec := &models.DstTunnelAddress{
			DstTunnelAddress: dstTunnelAddress,
			TrafficFilterRec: trafficFilterRec,
		}
		err := c.Db.InsertOrUpdateData(dstTunnelAddressRec, "dst_tunnel_address")
		if err != nil && err.Error() != lastInsertIdNotSupported {
			c.handleLoggingForError(util.InternalServerError, "Failed to save dst tunnel address record record for id"+
				filter.TrafficFilterId +toDatabase, appInstanceId)
			return err
		}
	}
	return nil
}

// Insert source tunnel port Record
func (c *AppRuleController) insertSrcTunnelPortRec(filter models.TrafficFilter, trafficFilterRec *models.TrafficFilterRec,
	appInstanceId string) error {

	for _, srcTunnelPort := range filter.SrcTunnelPort {
		srcTunnelPortRec := &models.SrcTunnelPort{
			SrcTunnelPort: srcTunnelPort,
			TrafficFilterRec: trafficFilterRec,
		}
		err := c.Db.InsertOrUpdateData(srcTunnelPortRec, "src_tunnel_port")
		if err != nil && err.Error() != lastInsertIdNotSupported {
			c.handleLoggingForError(util.InternalServerError, "Failed to save src tunnel port record for id"+
				filter.TrafficFilterId +toDatabase, appInstanceId)
			return err
		}
	}
	return nil
}

// Insert destination tunnel port record
func (c *AppRuleController) insertDstTunnelPortRec(filter models.TrafficFilter, trafficFilterRec *models.TrafficFilterRec,
	appInstanceId string) error {

	for _, dstTunnelPort := range filter.DstTunnelPort {
		dstTunnelPortRec := &models.DstTunnelPort{
			DstTunnelPort: dstTunnelPort,
			TrafficFilterRec: trafficFilterRec,
		}
		err := c.Db.InsertOrUpdateData(dstTunnelPortRec, "dst_tunnel_port")
		if err != nil && err.Error() != lastInsertIdNotSupported {
			c.handleLoggingForError(util.InternalServerError, "Failed to save dst tunnel port record for id"+
				filter.TrafficFilterId +toDatabase, appInstanceId)
			return err
		}
	}
	return nil
}

// Insert or update app traffic rule record
func (c *AppRuleController) InsertOrUpdateAppTrafficRuleRec(appRuleConfig *models.AppdRule,
	appdRuleRec *models.AppdRuleRec, appInstanceId string) error {
	for _, appRule := range appRuleConfig.AppTrafficRule {
		appTrafficRuleRec := &models.AppTrafficRuleRec{
			TrafficRuleId: appRule.TrafficRuleId,
			FilterType: appRule.FilterType,
			Priority: appRule.Priority,
			Action:  appRule.Action,
			AppdRule: appdRuleRec,
		}
		err := c.insertOrUpdateTrafficFltrRec(appRule, appTrafficRuleRec, appInstanceId)
		if err != nil {
			return err
		}

		err = c.insertOrUpdateDstInterfaceRec(appRule, appTrafficRuleRec, appInstanceId)
		if err != nil {
			return err
		}

		err = c.Db.InsertOrUpdateData(appTrafficRuleRec, "traffic_rule_id")
		if err != nil && err.Error() != lastInsertIdNotSupported {
			c.handleLoggingForError(util.InternalServerError, "Failed to save traffic rule record for id"+
				appRule.TrafficRuleId+toDatabase, appInstanceId)
			return err
		}
	}
	return nil
}

// Insert or update app dns rule record
func (c *AppRuleController) insertOrUpdateAppDnsRuleRec(appRuleConfig *models.AppdRule,
	appdRuleRec *models.AppdRuleRec, appInstanceId string) error {
	for _, appDnsRule := range appRuleConfig.AppDnsRule {
		appDnsRuleRec := &models.AppDnsRuleRec{
			DnsRuleId:appDnsRule.DnsRuleId,
			DomainName:appDnsRule.DomainName,
			IpAddressType: appDnsRule.IpAddressType,
			IpAddress     : appDnsRule.IpAddress,
			TTL      :appDnsRule.TTL,
			AppdRule: appdRuleRec,
		}

		err := c.Db.InsertOrUpdateData(appDnsRuleRec, "dns_rule_id")
		if err != nil && err.Error() != lastInsertIdNotSupported {
			c.handleLoggingForError(util.InternalServerError, "Failed to save dns rule record for id"+
				appDnsRule.DnsRuleId +toDatabase, appInstanceId)
			return err
		}
	}
	return nil
}

// Insert or update traffic filter child records
func (c *AppRuleController) insertOrUpdateTrafficFltrChildRecs(filter models.TrafficFilter,
	trafficFilterRec *models.TrafficFilterRec, appInstanceId string) error {
	err := c.InsertSrcAddressRec(filter, trafficFilterRec, appInstanceId)
	if err != nil {
		return err
	}

	err = c.insertSrcPortRec(filter, trafficFilterRec, appInstanceId)
	if err != nil {
		return err
	}

	err = c.insertDstAddressRec(filter, trafficFilterRec, appInstanceId)
	if err != nil {
		return err
	}

	err = c.insertDstPortRec(filter, trafficFilterRec, appInstanceId)
	if err != nil {
		return err
	}

	err = c.insertProtocolRec(filter, trafficFilterRec, appInstanceId)
	if err != nil {
		return err
	}

	err = c.insertTagRec(filter, trafficFilterRec, appInstanceId)
	if err != nil {
		return err
	}

	err = c.insertSrcTunnelAddressRec(filter, trafficFilterRec, appInstanceId)
	if err != nil {
		return err
	}

	err = c.insertDstTunnelAddressRec(filter, trafficFilterRec, appInstanceId)
	if err != nil {
		return err
	}

	err = c.insertSrcTunnelPortRec(filter, trafficFilterRec, appInstanceId)
	if err != nil {
		return err
	}

	err = c.insertDstTunnelPortRec(filter, trafficFilterRec, appInstanceId)
	if err != nil {
		return err
	}
	return nil
}

// Insert or update traffic filter record
func (c *AppRuleController) insertOrUpdateTrafficFltrRec(appRule models.AppTrafficRule,
	appTrafficRuleRec *models.AppTrafficRuleRec, appInstanceId string) error {
	for _, filter := range appRule.AppTrafficFilter {
		trafficFilterRec := &models.TrafficFilterRec{
			TrafficFilterId: util.GenerateUniqueId(),
			AppTrafficRuleRec:  appTrafficRuleRec,
			Qci: filter.Qci,
			Dscp: filter.Dscp,
			Tc: filter.Tc,
		}
		err :=c.insertOrUpdateTrafficFltrChildRecs(filter, trafficFilterRec, appInstanceId)
		if err != nil {
			log.Error("failed to insert child records:",err)
			return err
		}

		err = c.Db.InsertOrUpdateData(trafficFilterRec, "traffic_filter_id")
		if err != nil && err.Error() != lastInsertIdNotSupported {
			c.handleLoggingForError(util.InternalServerError, "Failed to save traffic filter record for id"+
				filter.TrafficFilterId +toDatabase, appInstanceId)
			return err
		}
	}
	return nil
}

// Insert or update destination interface record
func (c *AppRuleController) insertOrUpdateDstInterfaceRec(appRule models.AppTrafficRule,
	appTrafficRuleRec *models.AppTrafficRuleRec, appInstanceId string) error {
	for _, dstInterface := range appRule.DstInterface {
		dstInterfaceRec := &models.DstInterfaceRec{
			DstInterfaceId:util.GenerateUniqueId(),
			InterfaceType:dstInterface.InterfaceType,
			SrcMacAddress: dstInterface.SrcMacAddress,
			DstMacAddress: dstInterface.DstMacAddress,
			DstIpAddress :dstInterface.DstIpAddress,
			AppTrafficRuleRec:appTrafficRuleRec,
		}
		tunnelInfoRec := &models.TunnelInfoRec{
			TunnelInfoId:       util.GenerateUniqueId(),
			TunnelType : dstInterface.TunnelInfo.TunnelType,
			TunnelDstAddress: dstInterface.TunnelInfo.TunnelDstAddress,
			TunnelSrcAddress   :dstInterface.TunnelInfo.TunnelSrcAddress,
			TunnelSpecificData:dstInterface.TunnelInfo.TunnelSpecificData,
			DstInterfaceRec: dstInterfaceRec,
		}

		err := c.Db.InsertOrUpdateData(tunnelInfoRec, "tunnel_info_id")
		if err != nil && err.Error() != lastInsertIdNotSupported {
			c.handleLoggingForError(util.InternalServerError, "Failed to save dst interface record for id"+
				dstInterface.TunnelInfo.TunnelInfoId +toDatabase, appInstanceId)
			return err
		}
		err = c.Db.InsertOrUpdateData(dstInterfaceRec, "dst_interface_id")
		if err != nil && err.Error() != lastInsertIdNotSupported {
			c.handleLoggingForError(util.InternalServerError, "Failed to save dst interface record for id"+
				dstInterface.DstInterfaceId +toDatabase, appInstanceId)
			return err
		}
	}
	return nil
}

// Get appd rule sync information
func (c *AppRuleController) getAppdRuleSyncInfo() []models.AppdRuleRec {
	var appdRulesRec []models.AppdRuleRec
	var appdRulesSync []models.AppdRuleRec

	// Error handling to be further improved
	_, _ = c.Db.QueryTable(appdRule, &appdRulesRec, "tenant_id", c.Ctx.Input.Param(util.TenantId))
	for _, appdRuleRec := range appdRulesRec {
		_, _ = c.Db.LoadRelated(&appdRuleRec, "AppTrafficRuleRec")
		_, _ = c.Db.LoadRelated(&appdRuleRec, "AppDnsRuleRec")
		for _, trafficRule := range appdRuleRec.AppTrafficRuleRec {
			_, _ = c.Db.LoadRelated(trafficRule, "AppTrafficFilterRec")
			_, _ = c.Db.LoadRelated(trafficRule, "DstInterfaceRec")
			for _, traficFilterRec := range trafficRule.AppTrafficFilterRec {
				_, _ = c.Db.LoadRelated(traficFilterRec, "SrcAddress")
				_, _ = c.Db.LoadRelated(traficFilterRec, "SrcPort")
				_, _ = c.Db.LoadRelated(traficFilterRec, "DstAddress")
				_, _ = c.Db.LoadRelated(traficFilterRec, "DstPort")
				_, _ = c.Db.LoadRelated(traficFilterRec, "Protocol")
				_, _ = c.Db.LoadRelated(traficFilterRec, "Tag")
				_, _ = c.Db.LoadRelated(traficFilterRec, "SrcTunnelAddress")
				_, _ = c.Db.LoadRelated(traficFilterRec, "DstTunnelAddress")
				_, _ = c.Db.LoadRelated(traficFilterRec, "SrcTunnelPort")
				_, _ = c.Db.LoadRelated(traficFilterRec, "DstTunnelPort")

			}
			for _, dstInterface := range trafficRule.DstInterfaceRec {
				_, _ = c.Db.LoadRelated(dstInterface, "TunnelInfoRec")
			}
		}
		if !appdRuleRec.SyncStatus && strings.EqualFold(appdRuleRec.Origin, "mepm") {
			appdRulesSync = append(appdRulesSync, appdRuleRec)
		}
	}
	return appdRulesSync
}

// Get sync updated rules records
func (c *AppRuleController) SendSyncUpdatedRulesRecs(syncUpdatedRulesRecs models.SyncUpdatedRulesRecs,
	appdRulesSync []models.AppdRuleRec, clientIp string) {
	appRuleModelBytes, err := json.Marshal(syncUpdatedRulesRecs)
	if err != nil {
		c.WriteSyncErrorResponse(failedToMarshal, util.BadRequest)
		return
	}

	c.Ctx.ResponseWriter.Header().Set("Content-Type", applicationJson)
	c.Ctx.ResponseWriter.Header().Set("Accept", applicationJson)
	_, _ = c.Ctx.ResponseWriter.Write(appRuleModelBytes)

	for _, appRule := range appdRulesSync {
		appRule.SyncStatus = true
		err = c.Db.InsertOrUpdateData(&appRule, appdRuleId)
		if err != nil && err.Error() != lastInsertIdNotSupported {
			c.HandleLoggingForSyncError(clientIp, util.InternalServerError, "Failed to update sync status to true " +
				"to database with error: ." + err.Error())
			return
		}
	}
}

// Get traffic filter information
func (c *AppRuleController) GetTrafficFilterInfo(trafficFilter *models.TrafficFilterRec) models.TrafficFilter {
	var srcAddress           []string
	var srcPorts             []string
	var dstAddress           []string
	var dstPorts             []string
	var protocols            []string
	var tags                 []string
	var dstTunnelAddress     []string
	var srcTunnelAddress     []string
	var srcTunnelPorts       []string
	var dstTunnelPorts       []string

	for _, srcAddr := range trafficFilter.SrcAddress {
		srcAddress = append(srcAddress, srcAddr.SrcAddress)
	}
	for _, srcPort := range trafficFilter.SrcPort {
		srcPorts = append(srcPorts, srcPort.SrcPort)
	}
	for _, dstAddr := range trafficFilter.DstAddress {
		dstAddress = append(dstAddress, dstAddr.DstAddress)
	}
	for _, dstPort := range trafficFilter.DstPort {
		dstPorts = append(dstPorts, dstPort.DstPort)
	}
	for _, protocol := range trafficFilter.Protocol {
		protocols = append(protocols, protocol.Protocol)
	}
	for _, tag := range trafficFilter.Tag {
		tags = append(tags, tag.Tag)
	}
	for _, srcTunnelAddr := range trafficFilter.SrcTunnelAddress {
		srcTunnelAddress = append(srcTunnelAddress, srcTunnelAddr.SrcTunnelAddress)
	}
	for _, srcTunnelPort := range trafficFilter.SrcTunnelPort {
		srcTunnelPorts = append(srcTunnelPorts, srcTunnelPort.SrcTunnelPort)
	}
	for _, dstTunnelPort := range trafficFilter.DstTunnelPort {
		dstTunnelPorts = append(dstTunnelPorts, dstTunnelPort.DstTunnelPort)
	}
	trafficFil := models.TrafficFilter{
		TrafficFilterId  : trafficFilter.TrafficFilterId,
		Qci              : trafficFilter.Qci,
		Dscp            :  trafficFilter.Dscp,
		Tc               : trafficFilter.Tc,
		SrcAddress       : srcAddress,
		SrcPort          : srcPorts,
		DstAddress      :  dstAddress,
		DstPort         :  dstPorts,
		Protocol        :  protocols,
		Tag        :       tags,
		SrcTunnelAddress : srcTunnelAddress,
		DstTunnelAddress : dstTunnelAddress,
		SrcTunnelPort :    srcTunnelPorts,
		DstTunnelPort  :   dstTunnelPorts,
	}
	return trafficFil
}

// Get app traffic filter rules
func (c *AppRuleController) GetAppTrafficRules(appdRuleRec models.AppdRuleRec) []models.AppTrafficRule {
	var trafficFilters  []models.TrafficFilter
	var dstInterfaces   []models.DstInterface
	var appTrafficRules []models.AppTrafficRule

	for _, appTrafficRule := range appdRuleRec.AppTrafficRuleRec{
		for _, trafficFilter := range appTrafficRule.AppTrafficFilterRec {
			trafficFil := c.GetTrafficFilterInfo(trafficFilter)
			trafficFilters = append(trafficFilters, trafficFil)
		}

		for _, dstInterfaceRec := range appTrafficRule.DstInterfaceRec {
			tunnelInfo := models.TunnelInfo{
				TunnelInfoId: dstInterfaceRec.TunnelInfoRec.TunnelInfoId,
				TunnelType    : dstInterfaceRec.TunnelInfoRec.TunnelType,
				TunnelDstAddress :dstInterfaceRec.TunnelInfoRec.TunnelDstAddress,
				TunnelSrcAddress  : dstInterfaceRec.TunnelInfoRec.TunnelSrcAddress,
				TunnelSpecificData :dstInterfaceRec.TunnelInfoRec.TunnelSpecificData,
			}
			dstInterface := models.DstInterface{
				DstInterfaceId : dstInterfaceRec.DstInterfaceId,
				InterfaceType  : dstInterfaceRec.InterfaceType,
				SrcMacAddress  : dstInterfaceRec.SrcMacAddress,
				DstMacAddress  : dstInterfaceRec.DstMacAddress,
				DstIpAddress   : dstInterfaceRec.DstIpAddress,
				TunnelInfo     : tunnelInfo,
			}
			dstInterfaces = append(dstInterfaces, dstInterface)
		}
		appTraffic := models.AppTrafficRule{
			TrafficRuleId : appTrafficRule.TrafficRuleId,
			FilterType       : appTrafficRule.FilterType,
			Priority         :appTrafficRule.Priority,
			Action           :appTrafficRule.Action,
			AppTrafficFilter : trafficFilters,
			DstInterface   :dstInterfaces,
		}

		appTrafficRules = append(appTrafficRules, appTraffic)
	}
	return appTrafficRules
}

// Get sync updated rules records
func (c *AppRuleController) GetSyncUpdatedRulesRecs(syncUpdatedRulesRecords models.SyncUpdatedRulesRecords) models.SyncUpdatedRulesRecs {
	var syncUpdatedRulesRecs models.SyncUpdatedRulesRecs
	var appDnsRules     []models.AppDnsRule

	for _, appdRuleRec := range syncUpdatedRulesRecords.AppdRuleUpdatedRecs {
		appTrafficRules := c.GetAppTrafficRules(appdRuleRec)
		for _, appDnsRuleRec := range appdRuleRec.AppDnsRuleRec {
			appDnsRule := models.AppDnsRule{
				DnsRuleId: appDnsRuleRec.DnsRuleId,
				DomainName    : appDnsRuleRec.DomainName,
				IpAddressType : appDnsRuleRec.IpAddressType,
				IpAddress     : appDnsRuleRec.IpAddress,
				TTL           : appDnsRuleRec.TTL,
			}
			appDnsRules = append(appDnsRules, appDnsRule)
		}

		appRule := models.AppdRule{
			AppdRuleId:    appdRuleRec.AppdRuleId,
			TenantId  : appdRuleRec.TenantId,
			AppInstanceId  :appdRuleRec.AppInstanceId,
			AppName        :appdRuleRec.AppName,
			AppSupportMp1  :appdRuleRec.AppSupportMp1,
			AppTrafficRule: appTrafficRules,
			AppDnsRule    : appDnsRules,
			Origin : appdRuleRec.Origin,
			SyncStatus   :  appdRuleRec.SyncStatus,
		}

		syncUpdatedRulesRecs.AppdRuleUpdatedRecs = append(syncUpdatedRulesRecs.AppdRuleUpdatedRecs, appRule)
	}
	return syncUpdatedRulesRecs
}