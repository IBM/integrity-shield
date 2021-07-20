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

package resources

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	apiv1alpha1 "github.com/IBM/integrity-shield/integrity-shield-operator/api/v1alpha1"
	"github.com/open-policy-agent/frameworks/constraint/pkg/apis/templates/v1beta1"
)

// request handler config
func BuildConstraintTemplateForIShield(cr *apiv1alpha1.IntegrityShield) *v1beta1.ConstraintTemplate {
	crd := v1beta1.CRD{
		Spec: v1beta1.CRDSpec{
			Names: v1beta1.Names{
				Kind: "ManifestIntegrityConstraint",
			},
		},
	}
	targets := []v1beta1.Target{
		{
			Target: "admission.k8s.gatekeeper.sh",
			Rego:   cr.Spec.Rego,
		},
	}
	template := &v1beta1.ConstraintTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "manifestintegrityconstraint",
			Namespace: cr.Namespace,
		},
		Spec: v1beta1.ConstraintTemplateSpec{
			CRD:     crd,
			Targets: targets,
		},
	}
	return template
}