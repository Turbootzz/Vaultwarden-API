// Package v1alpha1 contains API Schema definitions for the secrets.vaultwarden.io v1alpha1 API group.
package v1alpha1

import (
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/scheme"
)

var (
	// GroupVersion is group version used to register these objects.
	GroupVersion = schema.GroupVersion{Group: "secrets.vaultwarden.io", Version: "v1alpha1"}

	// SchemeBuilder is used to add functions to this group's scheme.
	SchemeBuilder = &scheme.Builder{GroupVersion: GroupVersion}

	// AddToScheme adds the types in this group-version to the given scheme.
	AddToScheme = SchemeBuilder.AddToScheme
)

func init() {
	SchemeBuilder.Register(&VaultwardenSecret{}, &VaultwardenSecretList{})
}

// Resource takes an unqualified resource and returns a Group qualified GroupResource.
func Resource(resource string) schema.GroupResource {
	return GroupVersion.WithResource(resource).GroupResource()
}

// addKnownTypes adds our types to the given scheme.
func addKnownTypes(s *runtime.Scheme) error {
	s.AddKnownTypes(GroupVersion,
		&VaultwardenSecret{},
		&VaultwardenSecretList{},
	)
	return nil
}
