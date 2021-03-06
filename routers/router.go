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
	log "github.com/sirupsen/logrus"
	"mecm-apprulemgr/controllers"
	"mecm-apprulemgr/util"
	"os"
)

const RootPath string = "/apprulemgr/v1"

// Init application rule controller APIs
func init() {
	adapter := initDbAdapter()
	beego.Router(RootPath+"/health", &controllers.AppRuleController{Db: adapter}, "get:HealthCheck")
	beego.Router(RootPath+util.AppRuleConfigPath, &controllers.AppRuleController{Db: adapter}, "post:CreateAppRuleConfig")
	beego.Router(RootPath+util.AppRuleConfigPath, &controllers.AppRuleController{Db: adapter}, "put:UpdateAppRuleConfig")
	beego.Router(RootPath+util.AppRuleConfigPath, &controllers.AppRuleController{Db: adapter}, "delete:DeleteAppRuleConfig")
	beego.Router(RootPath+util.AppRuleConfigPath, &controllers.AppRuleController{Db: adapter}, "get:GetAppRuleConfig")
	beego.Router(RootPath+util.AppRuleSyncPath+"/sync_updated", &controllers.AppRuleController{Db: adapter}, "get:SynchronizeUpdatedRecords")
	beego.Router(RootPath+util.AppRuleSyncPath+"/sync_deleted", &controllers.AppRuleController{Db: adapter}, "get:SynchronizeDeletedRecords")
}

// Init Db adapter
func initDbAdapter() (pgDb controllers.Database) {
	adapter, err := controllers.GetDbAdapter()
	if err != nil {
		log.Error("failed to get database adapter")
		os.Exit(1)
	}
	return adapter
}
