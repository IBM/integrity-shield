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

package shield

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	miprofile "github.com/IBM/integrity-shield/admission-controller/pkg/apis/manifestintegrityprofile/v1alpha1"
	k8smnfconfig "github.com/IBM/integrity-shield/admission-controller/pkg/config"
	"github.com/pkg/errors"
	"github.com/sigstore/k8s-manifest-sigstore/pkg/k8smanifest"
	k8ssigutil "github.com/sigstore/k8s-manifest-sigstore/pkg/util"
	"github.com/sigstore/k8s-manifest-sigstore/pkg/util/kubeutil"
	"github.com/sigstore/k8s-manifest-sigstore/pkg/util/mapnode"
	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

const remoteRequestHandlerURL = "https://integrity-shield-api.k8s-manifest-sigstore.svc:8123/api/request"
const configKeyInConfigMap = "config.json"
const defaultPodNamespace = "k8s-manifest-sigstore"
const ishieldConfigMapName = "k8s-manifest-integrity-config"

func RequestHandlerController(remote bool, req admission.Request, paramObj *miprofile.ParameterObject) *ResultFromRequestHandler {
	r := &ResultFromRequestHandler{}
	if remote {
		log.Info("[DEBUG] remote request handler ", remoteRequestHandlerURL)
		// http call to remote request handler service
		input := &RemoteRequestHandlerInputMap{
			Request:   req,
			Parameter: *paramObj,
		}

		inputjson, _ := json.Marshal(input)
		transCfg := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client := &http.Client{Transport: transCfg}
		res, err := client.Post(remoteRequestHandlerURL, "application/json", bytes.NewBuffer([]byte(inputjson)))
		if err != nil {
			log.Error("Error reported from Remote RequestHandler", err.Error())
			return &ResultFromRequestHandler{
				Allow:   true,
				Message: "error but allow for development",
			}
		}
		if res.StatusCode != 200 {
			log.Error("Error reported from Remote RequestHandler: statusCode is not 200")
			return &ResultFromRequestHandler{
				Allow:   true,
				Message: "error but allow for development",
			}
		}
		body, err := ioutil.ReadAll(res.Body)
		if err != nil {
			log.Error("error: fail to read body: ", err)
			return &ResultFromRequestHandler{
				Allow:   true,
				Message: "error but allow for development",
			}
		}
		err = json.Unmarshal([]byte(string(body)), &r)
		if err != nil {
			log.Error("error: fail to Unmarshal: ", err)
			return &ResultFromRequestHandler{
				Allow:   true,
				Message: "error but allow for development",
			}
		}
		log.Info("[DEBUG] Response from remote request handler ", r)
		return r
	} else {
		// local request handler
		r = RequestHandler(req, paramObj)
	}
	return r
}

func RequestHandler(req admission.Request, paramObj *miprofile.ParameterObject) *ResultFromRequestHandler {
	// unmarshal admission request object
	// load Resource from Admission request
	var resource unstructured.Unstructured
	objectBytes := req.AdmissionRequest.Object.Raw
	err := json.Unmarshal(objectBytes, &resource)
	if err != nil {
		log.Errorf("failed to Unmarshal a requested object into %T; %s", resource, err.Error())
		return &ResultFromRequestHandler{
			Allow:   true,
			Message: "error but allow for development",
		}
	}

	// load shield config
	isconfig, err := loadShieldConfig()
	if err != nil {
		log.Errorf("failed to load shield config", err.Error())
		return &ResultFromRequestHandler{
			Allow:   true,
			Message: "error but allow for development",
		}
	}
	commonSkipUserMatched := false
	skipObjectMatched := false
	if isconfig != nil {
		//filter by user listed in common profile
		commonSkipUserMatched = isconfig.CommonProfile.SkipUsers.Match(resource, req.AdmissionRequest.UserInfo.Username)
		// ignore object
		skipObjectMatched = isconfig.CommonProfile.SkipObjects.Match(resource)
	}

	// TODO: Proccess with parameter
	//filter by user
	skipUserMatched := paramObj.SkipUsers.Match(resource, req.AdmissionRequest.UserInfo.Username)

	//check scope
	inScopeObjMatched := paramObj.InScopeObjects.Match(resource)

	//operation check
	updateRequestMatched := isUpdateRequest(req.AdmissionRequest.Operation)

	allow := true
	message := ""
	if skipUserMatched || commonSkipUserMatched {
		allow = true
		message = "ignore user config matched"
	} else if !inScopeObjMatched {
		allow = true
		message = "this resource is not in scope of verification"
	} else if skipObjectMatched {
		allow = true
		message = "this resource is not in scope of verification"
	} else {
		// get verifyOption and imageRef from Parameter
		imageRef := paramObj.ImageRef
		// prepare local key for verifyResource
		keyPath := ""
		if paramObj.KeySecertName != "" {
			keyPath, _ = k8smnfconfig.LoadKeySecret(paramObj.KeySecertNamespace, paramObj.KeySecertName)
		}
		vo := setVerifyOption(&paramObj.VerifyOption, isconfig)
		//vo := &(paramObj.VerifyOption)
		// call VerifyResource with resource, verifyOption, keypath, imageRef
		result, err := k8smanifest.VerifyResource(resource, imageRef, keyPath, vo)
		log.Info("[DEBUG] result from VerifyResource: ", result)
		if err != nil {
			log.Errorf("failed to check a requested resource; %s", err.Error())
			return &ResultFromRequestHandler{
				Allow:   true,
				Message: "error but allow for development",
			}
		}
		if result.InScope {
			if result.Verified {
				allow = true
				message = fmt.Sprintf("singed by a valid signer: %s", result.Signer)
			} else {
				allow = false
				message = "no signature found"
				if result.Diff != nil && result.Diff.Size() > 0 {
					message = fmt.Sprintf("diff found: %s", result.Diff.String())
				}
				if result.Signer != "" {
					message = fmt.Sprintf("signer config not matched, this is signed by %s", result.Signer)
				}
			}
			if updateRequestMatched && !result.Verified && result.Diff != nil && result.Diff.Size() > 0 {
				// TODO: mutation check for update request
				// mutation check..?
				isIgnoredByParam := checkIgnoreFields(resource, result.Diff, paramObj.IgnoreFields)
				isIgnoredByCommonProfile := checkIgnoreFields(resource, result.Diff, isconfig.CommonProfile.IgnoreFields)
				if isIgnoredByParam || isIgnoredByCommonProfile {
					allow = true
					message = "no mutation found"
				}
			}
		} else {
			allow = true
			message = "not protected"
		}
	}

	r := &ResultFromRequestHandler{
		Allow:   allow,
		Message: message,
	}

	// log
	log.Info("[DEBUG] result:", r.Message)

	return r
}

type ResultFromRequestHandler struct {
	Allow   bool
	Message string
}

type CommonProfile struct {
	SkipObjects  k8smanifest.ObjectReferenceList    `json:"skipObjects,omitempty"`
	SkipUsers    miprofile.ObjectUserBindingList    `json:"skipUsers,omitempty"`
	IgnoreFields k8smanifest.ObjectFieldBindingList `json:"ignoreFields,omitempty"`
}

type ShieldConfig struct {
	// Log        *LoggingScopeConfig `json:"log,omitempty"`
	// SideEffect *SideEffectConfig   `json:"sideEffect,omitempty"`
	CommonProfile CommonProfile `json:"commonProfile,omitempty"`
}

func isUpdateRequest(operation v1.Operation) bool {
	return (operation == v1.Update)
}

func checkIgnoreFields(resource unstructured.Unstructured, diff *mapnode.DiffResult, ignoreFields k8smanifest.ObjectFieldBindingList) bool {
	objectMatched, fields := ignoreFields.Match(resource)
	if objectMatched {
		for _, d := range diff.Items {
			var filtered bool
			for _, field := range fields {
				matched := k8ssigutil.MatchPattern(field, d.Key)
				if matched {
					filtered = true
				}
			}
			if !filtered {
				return false
			}
		}
		return true
	} else {
		return false
	}
}

func setVerifyOption(vo *k8smanifest.VerifyOption, isconfig *ShieldConfig) *k8smanifest.VerifyOption {
	if isconfig == nil {
		return vo
	}
	fields := k8smanifest.ObjectFieldBindingList{}
	fields = append(fields, vo.IgnoreFields...)
	fields = append(fields, isconfig.CommonProfile.IgnoreFields...)
	vo.IgnoreFields = fields
	log.Info("[DEBUG] setVerifyOption: ", vo)
	return vo
}

func loadShieldConfig() (*ShieldConfig, error) {
	log.Info("[DEBUG] loadShieldConfig: ", defaultPodNamespace, ", ", ishieldConfigMapName)
	obj, err := kubeutil.GetResource("v1", "ConfigMap", defaultPodNamespace, ishieldConfigMapName)
	if err != nil {
		if k8serrors.IsNotFound(err) {
			log.Info("[DEBUG] loadShieldConfig NotFound")
			return nil, nil
		}
		return nil, errors.Wrap(err, fmt.Sprintf("failed to get a configmap `%s` in `%s` namespace", ishieldConfigMapName, defaultPodNamespace))
	}
	objBytes, _ := json.Marshal(obj.Object)
	var cm corev1.ConfigMap
	_ = json.Unmarshal(objBytes, &cm)
	cfgBytes, found := cm.Data[configKeyInConfigMap]
	if !found {
		return nil, errors.New(fmt.Sprintf("`%s` is not found in configmap", configKeyInConfigMap))
	}
	var sc *ShieldConfig
	_ = json.Unmarshal([]byte(cfgBytes), &sc)
	// if err != nil {
	// 	return sc, errors.Wrap(err, fmt.Sprintf("failed to unmarshal config.yaml into %T", sc))
	// }
	log.Info("[DEBUG] ShieldConfig: ", sc)
	return sc, nil
}

type RemoteRequestHandlerInputMap struct {
	Request   admission.Request         `json:"request,omitempty"`
	Parameter miprofile.ParameterObject `json:"parameters,omitempty"`
}
