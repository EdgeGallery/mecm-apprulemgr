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

// Application rule manager APIs
package routers

import (
	"github.com/astaxie/beego"
	"mecm-apprulemgr/controllers"
	"mecm-apprulemgr/util"
)

const RootPath string = "/apprulemgr/v1"

// Init application rule controller APIs
func init() {
	beego.Router(RootPath+"/health", &controllers.AppRuleController{}, "get:HealthCheck")
	beego.Router(RootPath+util.AppRuleConfigPath, &controllers.AppRuleController{}, "post:CreateAppRuleConfig")
	beego.Router(RootPath+util.AppRuleConfigPath, &controllers.AppRuleController{}, "put:UpdateAppRuleConfig")
	beego.Router(RootPath+util.AppRuleConfigPath, &controllers.AppRuleController{}, "delete:DeleteAppRuleConfig")
	beego.Router(RootPath+util.AppRuleConfigPath, &controllers.AppRuleController{}, "get:GetAppRuleConfig")
}
