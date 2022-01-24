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

package models

import "github.com/astaxie/beego/orm"

// Init application info record
func init() {
	orm.RegisterModel(new(AppdRuleRec))
	orm.RegisterModel(new(AppTrafficRuleRec))
	orm.RegisterModel(new(AppDnsRuleRec))
	orm.RegisterModel(new(TrafficFilterRec))
	orm.RegisterModel(new(DstInterfaceRec))
	orm.RegisterModel(new(TunnelInfoRec))
	orm.RegisterModel(new(StaleAppdRule))
	orm.RegisterModel(new(SrcAddress))
	orm.RegisterModel(new(SrcPort))
	orm.RegisterModel(new(DstAddress))
	orm.RegisterModel(new(DstPort))
	orm.RegisterModel(new(Protocol))
	orm.RegisterModel(new(Tag))
	orm.RegisterModel(new(SrcTunnelAddress))
	orm.RegisterModel(new(DstTunnelAddress))
	orm.RegisterModel(new(SrcTunnelPort))
	orm.RegisterModel(new(DstTunnelPort))
}

// AppdRule information
type AppdRule struct {
	AppdRuleId     string            `orm:"pk" json:"appdRuleId,omitempty"`
	TenantId       string            `json:"tenantId,omitempty"`
	AppInstanceId  string            `json:"appInstanceId,omitempty"`
	AppName        string            `json:"appName" validate:"required,max=128,validateName"`
	AppSupportMp1  bool              `json:"appSupportMp1,omitempty"`
	AppTrafficRule []AppTrafficRule `orm:"reverse(many);on_delete(set_null)" json:"appTrafficRule" validate:"min=0,dive,max=16" `
	AppDnsRule     []AppDnsRule     `orm:"reverse(many);on_delete(set_null)" json:"appDnsRule" validate:"min=0,dive,max=32" `
	Origin         string            `orm:"default("meo")" json:"origin,omitempty"`
	SyncStatus     bool              `orm:"default(false)" json:"syncStatus,omitempty"`
}

// StaleAppdRule Stale appd rule which are deleted locally and pending to be synchronized to center.
type StaleAppdRule struct {
	AppdRuleId     string            `orm:"pk" json:"appdRuleId,omitempty"`
	TenantId       string            `json:"tenantId,omitempty"`
	AppInstanceId  string            `json:"appInstanceId,omitempty"`
}

// AppTrafficRule Represents traffic rule model
type AppTrafficRule struct {
	TrafficRuleId    string           `orm:"pk" json:"trafficRuleId" validate:"required,max=128"`
	FilterType       string           `json:"filterType" validate:"required,oneof=FLOW PACKET"`
	Priority         int              `json:"priority" validate:"required,gt=0,max=255"`
	Action           string           `json:"action" validate:"required,oneof=DROP PASSTHROUGH FORWARD_DECAPSULATED FORWARD_AS_IS DUPLICATED_DECAPSULATED DUPLICATE_AS_IS"`
	AppTrafficFilter []TrafficFilter `orm:"reverse(many);on_delete(set_null)" json:"trafficFilter" validate:"required,dive"`
	DstInterface     []DstInterface  `orm:"reverse(many);on_delete(set_null)" json:"dstInterface" validate:"omitempty,dive"`
}

// DstInterface Destination interface
type DstInterface struct {
	DstInterfaceId string          `orm:"pk" json:"dstInterfaceId" validate:"omitempty,max=128"`
	InterfaceType  string          `json:"interfaceType" validate:"omitempty`
	SrcMacAddress  string          `json:"srcMacAddress" validate:"omitempty`
	DstMacAddress  string          `json:"dstMacAddress" validate:"omitempty`
	DstIpAddress   string          `json:"dstIpAddress" validate:"omitempty`
	TunnelInfo     TunnelInfo     `orm:"reverse(one);on_delete(set_null)"`
}

// TunnelInfo Tunnel information
type TunnelInfo struct {
	TunnelInfoId       string        `orm:"pk" json:"tunnelInfoId" validate:"omitempty,max=128"`
	TunnelType         string        `json:"tunnelType" validate:"omitempty`
	TunnelDstAddress   string        `json:"tunnelDstAddress" validate:"omitempty`
	TunnelSrcAddress   string        `json:"tunnelSrcAddress" validate:"omitempty`
	TunnelSpecificData string        `json:"tunnelSpecificData" validate:"omitempty`
}

// TrafficFilter Represents traffic filter model
type TrafficFilter struct {
	TrafficFilterId  string          `orm:"pk" json:"trafficFilterId" validate:"omitempty`
	SrcAddress       []string        `orm:"-" json:"srcAddress" validate:"omitempty,dive,cidr"`
	SrcPort          []string        `orm:"-" json:"srcPort" validate:"omitempty,dive,gt=0,lte=65535"`
	DstAddress       []string        `orm:"-" json:"dstAddress" validate:"omitempty,dive,cidr"`
	DstPort          []string        `orm:"-" json:"dstPort" validate:"omitempty,dive,gt=0,lte=65535"`
	Protocol         []string        `orm:"-" json:"protocol" validate:"omitempty,dive,validateProtocol"`
	Qci              int             `json:"qCI" validate:"omitempty"`
	Dscp             int             `json:"dSCP" validate:"omitempty"`
	Tc               int             `json:"tC" validate:"omitempty"`
	Tag              []string        `orm:"-" json:"tag" validate:"omitempty"`
	SrcTunnelAddress []string        `orm:"-" json:"srcTunnelAddress" validate:"omitempty"`
	DstTunnelAddress []string        `orm:"-" json:"dstTunnelAddress" validate:"omitempty"`
	SrcTunnelPort    []string        `orm:"-" json:"srcTunnelPort" validate:"omitempty"`
	DstTunnelPort    []string        `orm:"-" json:"dstTunnelPort" validate:"omitempty"`
}

// AppDnsRule Represents dns rule model
type AppDnsRule struct {
	DnsRuleId     string    `orm:"pk" json:"dnsRuleId" validate:"required,max=128"`
	DomainName    string    `json:"domainName" validate:"required,max=128"`
	IpAddressType string    `json:"ipAddressType" validate:"required,oneof=IP_V4 IP_V6"`
	IpAddress     string    `json:"ipAddress" validate:"required,ip_addr"`
	TTL           int       `json:"ttl" validate:"omitempty,gte=0,max=4294967295"`
}

// OperationProgressModel Represents operation progress model
type OperationProgressModel struct {
	TaskId        string `json:"taskId"`
	AppInstanceId string `json:"appInstanceId"`
	ConfigResult  string `json:"configResult"`
	ConfigPhase   string `json:"configPhase"`
	Detailed      string `json:"detailed"`
}

// OperationFailureModel Represents operation failure model
type OperationFailureModel struct {
	Type   string `json:"type"`
	Title  string `json:"title"`
	Status int    `json:"status"`
	Detail string `json:"detail"`
}


// SyncUpdatedRulesRecs Appd rule updated record synchronization model.
type SyncUpdatedRulesRecs struct {
	AppdRuleUpdatedRecs []AppdRule `json:"appdRuleUpdatedRecs"`
}

// SyncUpdatedRulesRecords Appd rule updated record synchronization model.
type SyncUpdatedRulesRecords struct {
	AppdRuleUpdatedRecs []AppdRuleRec `json:"appdRuleUpdatedRecs"`
}

// SyncDeletedRulesRecords Appd rule updated record synchronization model.
type SyncDeletedRulesRecords struct {
	AppdRuleDeletedRecs []StaleAppdRule `json:"appdRuleDeletedRecs"`
}

// AppdRuleRec information
type AppdRuleRec struct {
	AppdRuleId     string            `orm:"pk" json:"appdRuleId,omitempty"`
	TenantId       string            `json:"tenantId,omitempty"`
	AppInstanceId  string            `json:"appInstanceId,omitempty"`
	AppName        string            `json:"appName" validate:"required,max=128,validateName"`
	AppSupportMp1  bool              `json:"appSupportMp1,omitempty"`
	AppTrafficRuleRec []*AppTrafficRuleRec `orm:"reverse(many);on_delete(set_null)" json:"appTrafficRule" validate:"min=0,dive,max=16" `
	AppDnsRuleRec     []*AppDnsRuleRec     `orm:"reverse(many);on_delete(set_null)" json:"appDnsRule" validate:"min=0,dive,max=32" `
	Origin         string            `orm:"default("meo")" json:"origin,omitempty"`
	SyncStatus     bool              `orm:"default(false)" json:"syncStatus,omitempty"`
}

// AppTrafficRuleRec Represents traffic rule model
type AppTrafficRuleRec struct {
	TrafficRuleId    string           `orm:"pk" json:"trafficRuleId" validate:"required,max=128"`
	FilterType       string           `json:"filterType" validate:"required,oneof=FLOW PACKET"`
	Priority         int              `json:"priority" validate:"required,gt=0,max=255"`
	Action           string           `json:"action" validate:"required,oneof=DROP PASSTHROUGH FORWARD_DECAPSULATED FORWARD_AS_IS DUPLICATED_DECAPSULATED DUPLICATE_AS_IS"`
	AppTrafficFilterRec []*TrafficFilterRec `orm:"reverse(many);on_delete(set_null)" json:"trafficFilter" validate:"required,dive"`
	DstInterfaceRec     []*DstInterfaceRec  `orm:"reverse(many);on_delete(set_null)" json:"dstInterface" validate:"omitempty,dive"`
	AppdRule         *AppdRuleRec        `orm:"rel(fk)"`
}

// DstInterfaceRec Destination interface
type DstInterfaceRec struct {
	DstInterfaceId string          `orm:"pk" json:"dstInterfaceId" validate:"omitempty,max=128"`
	InterfaceType  string          `json:"interfaceType" validate:"omitempty`
	SrcMacAddress  string          `json:"srcMacAddress" validate:"omitempty`
	DstMacAddress  string          `json:"dstMacAddress" validate:"omitempty`
	DstIpAddress   string          `json:"dstIpAddress" validate:"omitempty`
	TunnelInfoRec     *TunnelInfoRec     `orm:"reverse(one);on_delete(set_null)"`
	AppTrafficRuleRec *AppTrafficRuleRec `orm:"rel(fk)"`
}

// TunnelInfoRec Tunnel information
type TunnelInfoRec struct {
	TunnelInfoId       string        `orm:"pk" json:"tunnelInfoId" validate:"omitempty,max=128"`
	TunnelType         string        `json:"tunnelType" validate:"omitempty`
	TunnelDstAddress   string        `json:"tunnelDstAddress" validate:"omitempty`
	TunnelSrcAddress   string        `json:"tunnelSrcAddress" validate:"omitempty`
	TunnelSpecificData string        `json:"tunnelSpecificData" validate:"omitempty`
	DstInterfaceRec       *DstInterfaceRec `orm:"rel(one)"`
}

// TrafficFilterRec Represents traffic filter model
type TrafficFilterRec struct {
	TrafficFilterId  string          `orm:"pk" json:"trafficFilterId" validate:"omitempty`
	SrcAddress       []*SrcAddress    `orm:"reverse(many);on_delete(set_null)" json:"SrcAddress" validate:"omitempty,dive,cidr"`
	SrcPort          []*SrcPort        `orm:"reverse(many);on_delete(set_null)" json:"srcPort" validate:"omitempty,dive,gt=0,lte=65535"`
	DstAddress       []*DstAddress        `orm:"reverse(many);on_delete(set_null)" json:"dstAddress" validate:"omitempty,dive,cidr"`
	DstPort          []*DstPort        `orm:"reverse(many);on_delete(set_null)" json:"dstPort" validate:"omitempty,dive,gt=0,lte=65535"`
	Protocol         []*Protocol        `orm:"reverse(many);on_delete(set_null)" json:"protocol" validate:"omitempty,dive,validateProtocol"`
	Qci              int             `json:"qCI" validate:"omitempty"`
	Dscp             int             `json:"dSCP" validate:"omitempty"`
	Tc               int             `json:"tC" validate:"omitempty"`
	Tag              []*Tag        `orm:"reverse(many);on_delete(set_null)" json:"tag" validate:"omitempty"`
	SrcTunnelAddress []*SrcTunnelAddress        `orm:"reverse(many);on_delete(set_null)" json:"srcTunnelAddress" validate:"omitempty"`
	DstTunnelAddress []*DstTunnelAddress        `orm:"reverse(many);on_delete(set_null)" json:"dstTunnelAddress" validate:"omitempty"`
	SrcTunnelPort    []*SrcTunnelPort        `orm:"reverse(many);on_delete(set_null)" json:"drcTunnelPort" validate:"omitempty"`
	DstTunnelPort    []*DstTunnelPort        `orm:"reverse(many);on_delete(set_null)" json:"dstTunnelPort" validate:"omitempty"`
	AppTrafficRuleRec   *AppTrafficRuleRec `orm:"rel(fk)"`
}

// AppDnsRuleRec Represents dns rule model
type AppDnsRuleRec struct {
	DnsRuleId     string    `orm:"pk" json:"dnsRuleId" validate:"required,max=128"`
	DomainName    string    `json:"domainName" validate:"required,max=128"`
	IpAddressType string    `json:"ipAddressType" validate:"required,oneof=IP_V4 IP_V6"`
	IpAddress     string    `json:"ipAddress" validate:"required,ip_addr"`
	TTL           int       `json:"ttl" validate:"omitempty,gte=0,max=4294967295"`
	AppdRule      *AppdRuleRec `orm:"rel(fk)"`
}

// SrcAddress Represents source address
type SrcAddress struct {
	SrcAddress string `orm:"pk"`
	TrafficFilterRec *TrafficFilterRec `orm:"rel(fk)"`
}

// SrcPort Represents source port
type SrcPort struct {
	SrcPort string `orm:"pk"`
	TrafficFilterRec *TrafficFilterRec `orm:"rel(fk)"`
}

// DstAddress Represents destination address
type DstAddress struct {
	DstAddress string `orm:"pk"`
	TrafficFilterRec *TrafficFilterRec `orm:"rel(fk)"`
}

// DstPort Represents destination port
type DstPort struct {
	DstPort string `orm:"pk"`
	TrafficFilterRec *TrafficFilterRec `orm:"rel(fk)"`
}

// Protocol Represents protocol
type Protocol struct {
	Protocol string `orm:"pk"`
	TrafficFilterRec *TrafficFilterRec `orm:"rel(fk)"`
}

// Tag Represents Tag
type Tag struct {
	Tag string `orm:"pk"`
	TrafficFilterRec *TrafficFilterRec `orm:"rel(fk)"`
}

// SrcTunnelAddress Represents Source tunnel address
type SrcTunnelAddress struct {
	SrcTunnelAddress string `orm:"pk"`
	TrafficFilterRec *TrafficFilterRec `orm:"rel(fk)"`
}

// DstTunnelAddress Represents destination tunnel address
type DstTunnelAddress struct {
	DstTunnelAddress string `orm:"pk"`
	TrafficFilterRec *TrafficFilterRec `orm:"rel(fk)"`
}

// SrcTunnelPort Represents source tunnel port
type SrcTunnelPort struct {
	SrcTunnelPort string `orm:"pk"`
	TrafficFilterRec *TrafficFilterRec `orm:"rel(fk)"`
}

// DstTunnelPort Represents destination tunnel port
type DstTunnelPort struct {
	DstTunnelPort string `orm:"pk"`
	TrafficFilterRec *TrafficFilterRec `orm:"rel(fk)"`
}
