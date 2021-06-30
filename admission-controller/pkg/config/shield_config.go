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

type ShieldConfig struct {
	InScopeNamespaceSelector []string         `json:"inScopeNamespaceSelector,omitempty"`
	Allow                    []string         `json:"allow,omitempty"`
	Log                      LogConfig        `json:"log,omitempty"`
	SideEffect               SideEffectConfig `json:"sideEffect,omitempty"`
	Patch                    PatchConfig      `json:"skipObjects,omitempty"`
	Mode                     string           `json:"mode,omitempty"`
	Options                  []string
}

type LogConfig struct {
}

type SideEffectConfig struct {
	// Event
	CreateDenyEvent            bool `json:"createDenyEvent"`
	CreateIShieldResourceEvent bool `json:"createIShieldResourceEvent"`
	// MIP
	UpdateMIPStatusForDeniedRequest bool `json:"updateRSPStatusForDeniedRequest"`
}

type PatchConfig struct {
	Enabled bool `json:"enabled,omitempty"`
}
