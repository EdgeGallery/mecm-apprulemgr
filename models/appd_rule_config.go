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

type SampleStruct struct {
	SomeData string
}

type AppdRule struct {
	AppTrafficRule []AppTrafficRule `json:"appTrafficRule" validate:"min=0,dive,max=16" `
	AppDnsRule     []AppDnsRule     `json:"appDnsRule" validate:"min=0,dive,max=32" `
	AppName        string           `json:"appName" validate:"required,max=128,validateName"`
	AppSupportMp1  bool             `json:"appSupportMp1,omitempty"`
}

// Represents traffic rule model
type AppTrafficRule struct {
	TrafficRuleId    string          `json:"trafficRuleId" validate:"required,max=128"`
	FilterType       string          `json:"filterType" validate:"required,oneof=FLOW PACKET"`
	Priority         int             `json:"priority" validate:"required,gt=0,max=255"`
	Action           string          `json:"action" validate:"required,oneof=DROP PASSTHROUGH"`
	AppTrafficFilter []TrafficFilter `json:"trafficFilter" validate:"required,dive"`
}

// Represents dns rule model
type AppDnsRule struct {
	DnsRuleId     string `json:"dnsRuleId" validate:"required,max=128"`
	DomainName    string `json:"domainName" validate:"required,max=128"`
	IpAddressType string `json:"ipAddressType" validate:"required,oneof=IP_V4 IP_V6"`
	IpAddress     string `json:"ipAddress" validate:"required,ip_addr"`
	TTL           int    `json:"ttl" validate:"omitempty,gte=0,max=4294967295"`
}

// Represents traffic filter model
type TrafficFilter struct {
	SrcAddress []string `json:"srcAddress" validate:"omitempty,dive,cidr"`
	SrcPort    []string `json:"srcPort" validate:"omitempty,dive,gt=0,lte=65535"`
	DstAddress []string `json:"dstAddress" validate:"omitempty,dive,cidr"`
	DstPort    []string `json:"dstPort" validate:"omitempty,dive,gt=0,lte=65535"`
	Protocol   []string `json:"protocol" validate:"omitempty,dive,validateProtocol"`
	Qci        int      `json:"qCI" validate:"omitempty"`
	Dscp       int      `json:"dSCP" validate:"omitempty"`
	Tc         int      `json:"tC" validate:"omitempty"`
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
