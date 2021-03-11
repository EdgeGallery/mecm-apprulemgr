#!/bin/sh
# Copyright 2020 Huawei Technologies Co., Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# validates whether file exist
validate_file_exists() {
  file_path="$1"

  # checks variable is unset
  if [ -z "$file_path" ]; then
    echo "file path variable is not set"
    return 1
  fi

  # checks if file exists
  if [ ! -f "$file_path" ]; then
    echo "file does not exist"
    return 1
  fi

  return 0
}

# Validates if dir exists
validate_dir_exists()
{
   dir_path="$1"

   # checks if dir path var is unset
   if [ -z "$dir_path" ] ; then
     echo "dir path variable is not set"
     return 1
   fi

   # checks if dir exists
   if [ ! -d "$dir_path" ] ; then
     echo "dir does not exist"
     return 1
   fi

   return 0
}

# Validates if ip is valid
validate_ip()
{
 ip_var="$1"
    # checks if variable is unset
 if [ -z "$ip_var" ] ; then
    echo "ip is not set"
    return 1
 fi

 if ! echo "$ip_var" | grep -qE '^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.)' ; then
   return 1
 fi
 return 0
}

# Contain at most 63 characters
# Contain only lowercase alphanumeric characters or '-'
# Start with an alphanumeric character
# End with an alphanumeric character
validate_host_name()
{
 hostname="$1"
 len="${#hostname}"
 if [ "${len}" -gt "253" ] ; then
   return 1
 fi
 if ! echo "$hostname" | grep -qE '^([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])(\.([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9]))*$' ; then
   return 1
 fi
 return 0
}

# Validating if port is > 1 and < 65535 , not validating reserved port.
validate_port_num()
{
 portnum="$1"
 len="${#portnum}"
 if [ "${len}" -gt "5" ] ; then
   return 1
 fi
 if ! echo "$portnum" | grep -qE '^-?[0-9]+$' ; then
   return 1
 fi
 if [ "$portnum" -gt "65535" ] || [ "$portnum" -lt "1" ] ; then
   return 1
 fi
 return 0
}

# ssl parameters validation
validate_file_exists "/usr/app/ssl/server_tls.crt"
valid_server_certificate="$?"
if [ ! "$valid_server_certificate" -eq "0" ]; then
  echo "server certificate is missing"
  exit 1
fi

validate_file_exists "/usr/app/ssl/server_tls.key"
valid_server_certificate="$?"
if [ ! "$valid_server_certificate" -eq "0" ]; then
  echo "server key is missing"
  exit 1
fi

validate_file_exists "/usr/app/ssl/ca.crt"
valid_server_certificate="$?"
if [ ! "$valid_server_certificate" -eq "0" ]; then
  echo "ca cert is missing"
  exit 1
fi

if [ ! -z "$LOG_DIR" ] ; then
  validate_dir_exists "$LOG_DIR"
  valid_log_dir="$?"
  if [ ! "$valid_log_dir" -eq "0" ] ; then
    echo "log directory does not exist"
    exit 1
  fi
fi

validate_ip "$LISTEN_IP"
valid_listen_ip="$?"
if [ ! "$valid_listen_ip" -eq "0" ]; then
  echo "invalid ip address for listen ip"
  exit 1
fi

# app parameters validation
if [ ! -z "$MEP_SERVER_ADDR" ] ; then
  validate_host_name "$MEP_SERVER_ADDR"
  valid_mep_host_name="$?"
  if [ ! "$valid_mep_host_name" -eq "0" ] ; then
     echo "invalid mep host name"
     exit 1
  fi
fi

if [ ! -z "$MEP_SERVER_PORT" ] ; then
  validate_port_num "$MEP_SERVER_PORT"
  valid_mep_port="$?"
  if [ ! "$valid_mep_port" -eq "0" ] ; then
     echo "invalid mep port number"
     exit 1
  fi
fi

# db parameters validation
if [ ! -z "$APPRULEMGR_DB" ]; then
  validate_name "$APPRULEMGR_DB"
  valid_name="$?"
  if [ ! "$valid_name" -eq "0" ]; then
    echo "invalid DB name"
    exit 1
  fi
else
  export APPRULEMGR_DB=apprulemgrdb
fi

# db parameters validation
if [ ! -z "$APPRULEMGR_USER" ]; then
  validate_name "$APPRULEMGR_USER"
  valid_name="$?"
  if [ ! "$valid_name" -eq "0" ]; then
    echo "invalid DB user name"
    exit 1
  fi
else
  export APPRULEMGR_USER=apprulemgr
fi

if [ ! -z "$APPRULEMGR_DB_HOST" ]; then
  validate_host_name "$APPRULEMGR_DB_HOST"
  valid_db_host_name="$?"
  if [ ! "$valid_db_host_name" -eq "0" ]; then
    echo "invalid db host name"
    exit 1
  fi
else
  export APPRULEMGR_DB_HOST=mepm-postgres
fi

if [ ! -z "$APPRULEMGR_DB_PORT" ]; then
  validate_port_num "$APPRULEMGR_DB_PORT"
  valid_db_port="$?"
  if [ ! "$valid_db_port" -eq "0" ]; then
    echo "invalid apprulemgr db port number"
    exit 1
  fi
else
  export APPRULEMGR_DB_PORT=5432
fi

sed -i "s/^HTTPSAddr.*=.*$/HTTPSAddr = $(hostname -i)/g" conf/app.conf
sed -i "s/^dbAdapter.*=.*$/dbAdapter = ${APPRULEMGR_DB_ADAPTER}/g" conf/app.conf

cd /usr/app
umask 0027
$HOME/bin/apprulemgr
