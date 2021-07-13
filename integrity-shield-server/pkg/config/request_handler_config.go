//
// Copyright 2020 IBM Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package config

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/sigstore/k8s-manifest-sigstore/pkg/k8smanifest"
	"github.com/sigstore/k8s-manifest-sigstore/pkg/util/kubeutil"
	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

var logLevelMap = map[string]log.Level{
	"panic": log.PanicLevel,
	"fatal": log.FatalLevel,
	"error": log.ErrorLevel,
	"warn":  log.WarnLevel,
	"info":  log.InfoLevel,
	"debug": log.DebugLevel,
	"trace": log.TraceLevel,
}

type RequestHandlerConfig struct {
	ImageVerificationConfig ImageVerificationConfig `json:"imageVerificationConfig,omitempty"`
	KeyPathList             []string                `json:"keyPathList,omitempty"`
	SigStoreConfig          SigStoreConfig          `json:"sigStoreConfig,omitempty"`
	RequestFilterProfile    RequestFilterProfile    `json:"requestFilterProfile,omitempty"`
	Log                     LogConfig               `json:"log,omitempty"`
	Options                 []string
}

type LogConfig struct {
	Level    string `json:"level,omitempty"`
	FileDest string `json:"fileDest,omitempty"`
	Format   string `json:"format,omitempty"`
}

type ImageVerificationConfig struct {
}

type SigStoreConfig struct {
}

type RequestFilterProfile struct {
	SkipObjects  k8smanifest.ObjectReferenceList    `json:"skipObjects,omitempty"`
	SkipUsers    ObjectUserBindingList              `json:"skipUsers,omitempty"`
	IgnoreFields k8smanifest.ObjectFieldBindingList `json:"ignoreFields,omitempty"`
}

func SetupLogger(config LogConfig, req admission.Request) {
	logLevelStr := config.Level
	if logLevelStr == "" {
		logLevelStr = "info"
	}
	logLevel, ok := logLevelMap[logLevelStr]
	if !ok {
		logLevel = log.InfoLevel
	}

	log.SetLevel(logLevel)
	// format
	if config.Format == "json" {
		log.SetFormatter(&log.JSONFormatter{TimestampFormat: time.RFC3339Nano})
	}
}

func LoadKeySecret(keySecertNamespace, keySecertName string) (string, error) {
	obj, err := kubeutil.GetResource("v1", "Secret", keySecertNamespace, keySecertName)
	if err != nil {
		return "", errors.Wrap(err, fmt.Sprintf("failed to get a secret `%s` in `%s` namespace", keySecertName, keySecertNamespace))
	}
	objBytes, _ := json.Marshal(obj.Object)
	var secret v1.Secret
	_ = json.Unmarshal(objBytes, &secret)
	keyDir := fmt.Sprintf("/tmp/%s/%s/", keySecertNamespace, keySecertName)
	sumErr := []string{}
	keyPath := ""
	for fname, keyData := range secret.Data {
		fpath := filepath.Join(keyDir, fname)
		err := ioutil.WriteFile(fpath, keyData, 0644)
		if err != nil {
			sumErr = append(sumErr, err.Error())
			continue
		}
		keyPath = fpath
		break
	}
	if keyPath == "" && len(sumErr) > 0 {
		return "", errors.New(fmt.Sprintf("failed to save secret data as a file; %s", strings.Join(sumErr, "; ")))
	}
	if keyPath == "" {
		return "", errors.New(fmt.Sprintf("no key files are found in the secret `%s` in `%s` namespace", keySecertName, keySecertNamespace))
	}

	return keyPath, nil
}
