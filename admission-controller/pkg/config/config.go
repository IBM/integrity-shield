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
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	miprofile "github.com/IBM/integrity-shield/admission-controller/pkg/apis/manifestintegrityprofile/v1alpha1"
	mipclient "github.com/IBM/integrity-shield/admission-controller/pkg/client/manifestintegrityprofile/clientset/versioned/typed/manifestintegrityprofile/v1alpha1"
	"github.com/sigstore/k8s-manifest-sigstore/pkg/util/kubeutil"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func GetParametersFromConstraint(constraint miprofile.ManifestIntegrityProfileSpec) *miprofile.ParameterObject {
	return &constraint.Parameters
}

func LoadConstraints() ([]miprofile.ManifestIntegrityProfileSpec, error) {
	manifestIntegrityProfileList, err := loadManifestIntegiryProfiles()
	if err != nil {
		return []miprofile.ManifestIntegrityProfileSpec{}, err
	}
	if manifestIntegrityProfileList == nil {
		return []miprofile.ManifestIntegrityProfileSpec{}, nil
	}
	constraints := loadConstraintsFromProfileList(manifestIntegrityProfileList)
	return constraints, nil
}

func loadConstraintsFromProfileList(miplist *miprofile.ManifestIntegrityProfileList) []miprofile.ManifestIntegrityProfileSpec {
	var constraints []miprofile.ManifestIntegrityProfileSpec
	for _, mip := range miplist.Items {
		constraints = append(constraints, mip.Spec)
	}
	return constraints
}

func loadManifestIntegiryProfiles() (*miprofile.ManifestIntegrityProfileList, error) {
	// TODO: kubeconfig
	config, err := kubeutil.GetKubeConfig()
	if err != nil {
		return nil, nil
	}
	clientset, err := mipclient.NewForConfig(config)
	if err != nil {
		log.Error(err)
		return nil, nil
	}
	miplist, err := clientset.ManifestIntegrityProfiles().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		log.Error("failed to get ManifestIntegrityProfiles:", err.Error())
		return nil, nil
	}
	return miplist, nil
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
