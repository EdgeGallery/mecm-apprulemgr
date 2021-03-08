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

// db controller
package controllers

import (
	"errors"
	"fmt"
	"github.com/astaxie/beego"
	"os"
	"regexp"
	"strings"
	"unsafe"

	"github.com/astaxie/beego/orm"
	log "github.com/sirupsen/logrus"
)

const (
	defaultAlias     string = "default"
	driverName       string = "postgres"
	minPasswordSize         = 8
	maxPasswordSize         = 16
	specialCharRegex string = `['~!@#$%^&()-_=+\|[{}\];:'",<.>/?]`
	singleDigitRegex string = `\d`
	lowerCaseRegex   string = `[a-z]`
	upperCaseRegex   string = `[A-Z]`
	maxPasswordCount        = 2
	maxIdLength             = 32
)

// Pg database
type PgDb struct {
	ormer orm.Ormer
}

// Constructor of PluginAdapter
func (db *PgDb) initOrmer() (err1 error) {
	defer func() {
		if err := recover(); err != nil {
			log.Error("panic handled:", err)
			err1 = fmt.Errorf("recover panic as %s", err)
		}
	}()
	o := orm.NewOrm()
	err1 = o.Using(defaultAlias)
	if err1 != nil {
		return err1
	}
	db.ormer = o

	return nil
}

// Insert or update data into lcmcontroller
func (db *PgDb) InsertOrUpdateData(data interface{}, cols ...string) (err error) {
	_, err = db.ormer.InsertOrUpdate(data, cols...)
	return err
}

// Read data from lcmcontroller
func (db *PgDb) ReadData(data interface{}, cols ...string) (err error) {
	err = db.ormer.Read(data, cols...)
	return err
}

// Delete data from lcmcontroller
func (db *PgDb) DeleteData(data interface{}, cols ...string) (err error) {
	_, err = db.ormer.Delete(data, cols...)
	return err
}

// Init database
func (db *PgDb) InitDatabase() error {
	dbUser := getDbUser()
	dbPwd := []byte(os.Getenv("AppRuleMgr_DB_PASSWORD"))
	dbName := getDbName()
	dbHost := getDbHost()
	dbPort := getDbPort()
	dbSslMode := getAppConfig("DB_SSL_MODE")
	dbSslRootCert := getAppConfig("DB_SSL_ROOT_CERT")

	dbPwdStr := string(dbPwd)
	clearByteArray(dbPwd)
	dbParamsAreValid, validateDbParamsErr := validateDbParams(dbPwdStr)
	if validateDbParamsErr != nil || !dbParamsAreValid {
		return errors.New("failed to validate db parameters")
	}
	registerDriverErr := orm.RegisterDriver(driverName, orm.DRPostgres)
	if registerDriverErr != nil {
		log.Error("Failed to register driver")
		return registerDriverErr
	}

	var b strings.Builder
	fmt.Fprintf(&b, "user=%s password=%s dbname=%s host=%s port=%s sslmode=%s sslrootcert=%s", dbUser, dbPwdStr,
		dbName, dbHost, dbPort, dbSslMode, dbSslRootCert)
	bStr := b.String()

	registerDataBaseErr := orm.RegisterDataBase(defaultAlias, driverName, bStr)
	//clear bStr
	bKey1 := *(*[]byte)(unsafe.Pointer(&bStr))
	clearByteArray(bKey1)

	bKey := *(*[]byte)(unsafe.Pointer(&dbPwdStr))
	clearByteArray(bKey)

	if registerDataBaseErr != nil {
		log.Error("Failed to register database")
		return registerDataBaseErr
	}

	errRunSyncdb := orm.RunSyncdb(defaultAlias, false, false)
	if errRunSyncdb != nil {
		log.Error("Failed to sync database.")
		return errRunSyncdb
	}

	err := db.initOrmer()
	if err != nil {
		log.Error("Failed to init ormer")
		return err
	}

	return nil
}

// Get db user
func getDbUser() string {
	dbUser := os.Getenv("AppRuleMgr_USER")
	return dbUser
}

// Get database name
func getDbName() string {
	dbName := os.Getenv("AppRuleMgr_DB")
	return dbName
}

// Get database host
func getDbHost() string {
	dbHost := os.Getenv("AppRuleMgr_DB_HOST")
	return dbHost
}

// Get database port
func getDbPort() string {
	dbPort := os.Getenv("AppRuleMgr_DB_PORT")
	return dbPort
}

// Get app configuration
func getAppConfig(k string) string {
	return beego.AppConfig.String(k)
}

// Clear byte array from memory
func ClearByteArray(data []byte) {
	for i := 0; i < len(data); i++ {
		data[i] = 0
	}
}

// Validate password
func validatePassword(password *[]byte) (bool, error) {
	if len(*password) >= minPasswordSize && len(*password) <= maxPasswordSize {
		// password must satisfy any two conditions
		pwdValidCount := getPasswordValidCount(password)
		if pwdValidCount < maxPasswordCount {
			return false, errors.New("password must contain at least two types of the either one lowercase" +
				" character, one uppercase character, one digit or one special character")
		}
	} else {
		return false, errors.New("password must have minimum length of 8 and maximum of 16")
	}
	return true, nil
}

// To get password valid count
func getPasswordValidCount(password *[]byte) int {
	var pwdValidCount = 0
	pwdIsValid, err := regexp.Match(singleDigitRegex, *password)
	if pwdIsValid && err == nil {
		pwdValidCount++
	}
	pwdIsValid, err = regexp.Match(lowerCaseRegex, *password)
	if pwdIsValid && err == nil {
		pwdValidCount++
	}
	pwdIsValid, err = regexp.Match(upperCaseRegex, *password)
	if pwdIsValid && err == nil {
		pwdValidCount++
	}
	// space validation for password complexity is not added
	// as jwt decrypt fails if space is included in password
	pwdIsValid, err = regexp.Match(specialCharRegex, *password)
	if pwdIsValid && err == nil {
		pwdValidCount++
	}
	return pwdValidCount
}

// Validate db parameters
func validateDbParams(dbPwd string) (bool, error) {
	dbPwdBytes := []byte(dbPwd)
	dbPwdIsValid, validateDbPwdErr := validatePassword(&dbPwdBytes)
	if validateDbPwdErr != nil || !dbPwdIsValid {
		return dbPwdIsValid, validateDbPwdErr
	}
	return true, nil
}

// Clear byte array from memory
func clearByteArray(data []byte) {
	for i := 0; i < len(data); i++ {
		data[i] = 0
	}
}
