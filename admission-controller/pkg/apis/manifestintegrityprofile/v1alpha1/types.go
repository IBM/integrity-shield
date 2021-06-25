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

package v1alpha1

import (
	"github.com/jinzhu/copier"
	"github.com/yuji-watanabe-jp/k8s-manifest-sigstore/pkg/k8smanifest"
	k8smnfutil "github.com/yuji-watanabe-jp/k8s-manifest-sigstore/pkg/util"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

var layout = "2006-01-02 15:04:05"

const maxHistoryLength = 3

// ManifestIntegrityProfileSpec defines the desired state of AppEnforcePolicy
type ManifestIntegrityProfileSpec struct {
	Match      MatchCondition  `json:"match,omitempty"`
	Parameters ParameterObject `json:"parameters,omitempty"`
}

type MatchCondition struct {
	Kinds              []string `json:"kinds,omitempty"`
	Namespaces         []string `json:"namespaces,omitempty"`
	ExcludedNamespaces []string `json:"excludednamespaces,omitempty"`
}

type ParameterObject struct {
	k8smanifest.VerifyOption `json:""`
	InScopeObjects           k8smanifest.ObjectReferenceList `json:"inScopeObjects,omitempty"`
	SkipUsers                ObjectUserBindingList           `json:"skipUsers,omitempty"`
	KeySecertName            string                          `json:"keySecretName,omitempty"`
	KeySecertNamespace       string                          `json:"keySecretNamespace,omitempty"`
	ImageRef                 string                          `json:"imageRef,omitempty"`
}

type ObjectUserBindingList []ObjectUserBinding

type ObjectUserBinding struct {
	Objects k8smanifest.ObjectReferenceList `json:"objects,omitempty"`
	Users   []string                        `json:"users,omitempty"`
}

// ManifestIntegrityProfileStatus defines the observed state of AppEnforcePolicy
type ManifestIntegrityProfileStatus struct {
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +resource:path=manifestintegrityprofile,scope=Cluster

// EnforcePolicy is the CRD. Use this command to generate deepcopy for it:
// ./k8s.io/code-generator/generate-groups.sh all github.com/IBM/pas-client-go/pkg/crd/packageadmissionsignature/v1/apis github.com/IBM/pas-client-go/pkg/crd/ "packageadmissionsignature:v1"
// For more details of code-generator, please visit https://github.com/kubernetes/code-generator
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// ManifestIntegrityProfile is the CRD. Use this command to generate deepcopy for it:
type ManifestIntegrityProfile struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ManifestIntegrityProfileSpec   `json:"spec,omitempty"`
	Status ManifestIntegrityProfileStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ManifestIntegrityProfileList contains a list of ManifestIntegrityProfile
type ManifestIntegrityProfileList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ManifestIntegrityProfile `json:"items"`
}

func (p *ParameterObject) DeepCopyInto(p2 *ParameterObject) {
	copier.Copy(&p2, &p)
}

func (p *MatchCondition) DeepCopyInto(p2 *MatchCondition) {
	copier.Copy(&p2, &p)
}

func (u ObjectUserBinding) Match(obj unstructured.Unstructured, username string) bool {
	if u.Objects.Match(obj) {
		if k8smnfutil.MatchWithPatternArray(username, u.Users) {
			return true
		}
	}
	return false
}

func (l ObjectUserBindingList) Match(obj unstructured.Unstructured, username string) bool {
	if len(l) == 0 {
		return false
	}
	for _, u := range l {
		if u.Match(obj, username) {
			return true
		}
	}
	return false
}
