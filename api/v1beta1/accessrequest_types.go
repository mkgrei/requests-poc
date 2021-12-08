/*
Copyright 2021.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1beta1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// AccessRequestSpec defines the desired state of AccessRequest
type AccessRequestSpec struct {
	PubKey string `json:"pubKey,omitempty"`
}

// AccessRequestStatus defines the observed state of AccessRequest
type AccessRequestStatus struct {
	Accepted bool   `json:"accepted,omitempty"`
	Ready    bool   `json:"ready,omitempty"`
	Key      string `json:"key,omitempty"`
	Token    string `json:"token,omitempty"`
	CA       string `json:"ca,omitempty"`
}

//+kubebuilder:resource:path=accessrequests,scope=Cluster
//+kubebuilder:object:root=true
//+kubebuilder:subresource:status
//+kubebuilder:printcolumn:name="Ready",type="string",JSONPath=".status.ready"

// AccessRequest is the Schema for the accessrequests API
type AccessRequest struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AccessRequestSpec   `json:"spec,omitempty"`
	Status AccessRequestStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// AccessRequestList contains a list of AccessRequest
type AccessRequestList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AccessRequest `json:"items"`
}

func init() {
	SchemeBuilder.Register(&AccessRequest{}, &AccessRequestList{})
}
