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
	AppTrafficRule []AppTrafficRule `json:"appTrafficRule"`
	AppDnsRule     []AppDnsRule     `json:"appDnsRule"`
	AppName        string           `json:"appName"`
	AppSupportMp1  bool             `json:"appSupportMp1"`
}

// Represents traffic rule model
type AppTrafficRule struct {
	TrafficRuleId    string          `json:"trafficRuleId"`
	FilterType       string          `json:"filterType"`
	Priority         int             `json:"priority"`
	Action           string          `json:"action"`
	AppTrafficFilter []TrafficFilter `json:"trafficFilter"`
}

// Represents dns rule model
type AppDnsRule struct {
	DnsRuleId     string `json:"dnsRuleId"`
	DomainName    string `json:"domainName"`
	IpAddressType string `json:"ipAddressType"`
	IpAddress     string `json:"ipAddress"`
	TTL           int    `json:"ttl"`
}

// Represents traffic filter model
type TrafficFilter struct {
	SrcAddress []string `json:"srcAddress"`
	SrcPort    []string `json:"srcPort"`
	DstAddress []string `json:"dstAddress"`
	DstPort    []string `json:"dstPort"`
	Protocol   []string `json:"protocol"`
	Qci        int      `json:"qCI"`
	Dscp       int      `json:"dSCP"`
	Tc         int      `json:"tC"`
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
