package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// VaultwardenSecretDataItem maps a Kubernetes Secret key to a Vaultwarden item.
type VaultwardenSecretDataItem struct {
	// Key is the key name in the resulting Kubernetes Secret.
	Key string `json:"key"`
	// VaultwardenSecret is the item name to look up in Vaultwarden (case-insensitive).
	VaultwardenSecret string `json:"vaultwardenSecret"`
}

// VaultwardenSecretSpec defines the desired state of VaultwardenSecret.
type VaultwardenSecretSpec struct {
	// SyncInterval is how often to re-sync this secret from Vaultwarden.
	// Defaults to "5m". Must be a valid Go duration string.
	// +kubebuilder:default="5m"
	// +optional
	SyncInterval string `json:"syncInterval,omitempty"`

	// Data is the list of Vaultwarden items to fetch and store in the Kubernetes Secret.
	// +kubebuilder:validation:MinItems=1
	Data []VaultwardenSecretDataItem `json:"data"`
}

// VaultwardenSecretStatus defines the observed state of VaultwardenSecret.
type VaultwardenSecretStatus struct {
	// Ready indicates whether the secret has been successfully synced.
	Ready bool `json:"ready"`

	// LastSyncTime is the timestamp of the last successful sync.
	// +optional
	LastSyncTime *metav1.Time `json:"lastSyncTime,omitempty"`

	// LastSyncError contains the error message from the last failed sync.
	// +optional
	LastSyncError string `json:"lastSyncError,omitempty"`

	// ObservedGeneration is the most recent generation observed by the controller.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Conditions represent the latest available observations of the resource's state.
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=vws,scope=Namespaced
// +kubebuilder:printcolumn:name="Ready",type=boolean,JSONPath=".status.ready"
// +kubebuilder:printcolumn:name="Last Sync",type=date,JSONPath=".status.lastSyncTime"
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=".metadata.creationTimestamp"

// VaultwardenSecret is the Schema for the vaultwardensecrets API.
type VaultwardenSecret struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   VaultwardenSecretSpec   `json:"spec,omitempty"`
	Status VaultwardenSecretStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// VaultwardenSecretList contains a list of VaultwardenSecret.
type VaultwardenSecretList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []VaultwardenSecret `json:"items"`
}
