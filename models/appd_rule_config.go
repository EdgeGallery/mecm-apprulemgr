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

type SampleStruct struct {
	SomeData string
}

// Init application info record
func init() {
	orm.RegisterModel(new(AppdRule))
	orm.RegisterModel(new(AppTrafficRule))
	orm.RegisterModel(new(AppDnsRule))
	orm.RegisterModel(new(TrafficFilter))
	orm.RegisterModel(new(DstInterface))
	orm.RegisterModel(new(TunnelInfo))
}

type AppdRule struct {
	AppdRuleId     string            `orm:"pk" json:"appdRuleId,omitempty"`
	TenantId       string            `json:"tenantId,omitempty"`
	AppInstanceId  string            `json:"appInstanceId,omitempty"`
	AppName        string            `json:"appName" validate:"required,max=128,validateName"`
	AppSupportMp1  bool              `json:"appSupportMp1,omitempty"`
	AppTrafficRule []*AppTrafficRule `orm:"reverse(many);on_delete(set_null)" json:"appTrafficRule" validate:"min=0,dive,max=16" `
	AppDnsRule     []*AppDnsRule     `orm:"reverse(many);on_delete(set_null)" json:"appDnsRule" validate:"min=0,dive,max=32" `
}

// Represents traffic rule model
type AppTrafficRule struct {
	TrafficRuleId    string           `orm:"pk" json:"trafficRuleId" validate:"required,max=128"`
	FilterType       string           `json:"filterType" validate:"required,oneof=FLOW PACKET"`
	Priority         int              `json:"priority" validate:"required,gt=0,max=255"`
	Action           string           `json:"action" validate:"required,oneof=DROP PASSTHROUGH"`
	AppTrafficFilter []*TrafficFilter `orm:"reverse(many);on_delete(set_null)" json:"trafficFilter" validate:"required,dive"`
	DstInterface     []*DstInterface  `orm:"reverse(many);on_delete(set_null)" json:"dstInterface" validate:"omitempty,dive"`
	AppdRule         *AppdRule        `orm:"rel(fk)"`
}

// Destination interface
type DstInterface struct {
	DstInterfaceId string          `orm:"pk" json:"dstInterfaceId" validate:"omitempty,max=128"`
	InterfaceType  string          `json:"interfaceType" validate:"omitempty`
	SrcMacAddress  string          `json:"srcMacAddress" validate:"omitempty`
	DstMacAddress  string          `json:"dstMacAddress" validate:"omitempty`
	DstIpAddress   string          `json:"dstIpAddress" validate:"omitempty`
	TunnelInfo     *TunnelInfo     `orm:"reverse(one);on_delete(set_null)"`
	AppTrafficRule *AppTrafficRule `orm:"rel(fk)"`
}

// Tunnel information
type TunnelInfo struct {
	TunnelInfoId       string        `orm:"pk" json:"tunnelInfoId" validate:"omitempty,max=128"`
	TunnelType         string        `json:"tunnelType" validate:"omitempty`
	TunnelDstAddress   string        `json:"tunnelDstAddress" validate:"omitempty`
	TunnelSrcAddress   string        `json:"tunnelSrcAddress" validate:"omitempty`
	TunnelSpecificData string        `json:"tunnelSpecificData" validate:"omitempty`
	DstInterface       *DstInterface `orm:"rel(one)"`
}

// Represents traffic filter model
type TrafficFilter struct {
	TrafficFilterId  string          `orm:"pk"`
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
	SrcTunnelPort    []string        `orm:"-" json:"drcTunnelPort" validate:"omitempty"`
	DstTunnelPort    []string        `orm:"-" json:"dstTunnelPort" validate:"omitempty"`
	AppTrafficRule   *AppTrafficRule `orm:"rel(fk)"`
}

// Represents dns rule model
type AppDnsRule struct {
	DnsRuleId     string    `orm:"pk" json:"dnsRuleId" validate:"required,max=128"`
	DomainName    string    `json:"domainName" validate:"required,max=128"`
	IpAddressType string    `json:"ipAddressType" validate:"required,oneof=IP_V4 IP_V6"`
	IpAddress     string    `json:"ipAddress" validate:"required,ip_addr"`
	TTL           int       `json:"ttl" validate:"omitempty,gte=0,max=4294967295"`
	AppdRule      *AppdRule `orm:"rel(fk)"`
}

// Represents operation progress model
type OperationProgressModel struct {
	TaskId        string `json:"taskId"`
	AppInstanceId string `json:"appInstanceId"`
	ConfigResult  string `json:"configResult"`
	ConfigPhase   string `json:"configPhase"`
	Detailed      string `json:"detailed"`
}

// Represents operation failure model
type OperationFailureModel struct {
	Type   string `json:"type"`
	Title  string `json:"title"`
	Status int    `json:"status"`
	Detail string `json:"detail"`
}
