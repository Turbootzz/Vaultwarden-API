// Package controller implements the VaultwardenSecret reconciler.
package controller

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	secretsv1alpha1 "github.com/Turbootzz/vaultwarden-api/internal/operator/api/v1alpha1"
	"github.com/Turbootzz/vaultwarden-api/internal/vaultwarden"
)

const (
	finalizerName        = "secrets.vaultwarden.io/finalizer"
	managedByLabel       = "vaultwarden-operator"
	conditionTypeReady   = "Ready"
	conditionTypeFailed  = "SyncFailed"
	defaultSyncInterval  = 5 * time.Minute
)

// VaultwardenSecretReconciler reconciles a VaultwardenSecret object.
type VaultwardenSecretReconciler struct {
	client.Client
	Scheme      *runtime.Scheme
	VaultClient *vaultwarden.Client
}

// +kubebuilder:rbac:groups=secrets.vaultwarden.io,resources=vaultwardensecrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=secrets.vaultwarden.io,resources=vaultwardensecrets/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=secrets.vaultwarden.io,resources=vaultwardensecrets/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch
// +kubebuilder:rbac:groups=coordination.k8s.io,resources=leases,verbs=get;list;watch;create;update;patch;delete

// Reconcile is the main reconciliation loop for VaultwardenSecret resources.
func (r *VaultwardenSecretReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// 1. Fetch the VaultwardenSecret CR.
	vws := &secretsv1alpha1.VaultwardenSecret{}
	if err := r.Get(ctx, req.NamespacedName, vws); err != nil {
		// Not found means deleted — nothing to do.
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// 2. Handle deletion: remove finalizer so the object can be garbage collected.
	// Owner references on the managed Secret ensure it is cascade-deleted.
	if !vws.DeletionTimestamp.IsZero() {
		if controllerutil.ContainsFinalizer(vws, finalizerName) {
			controllerutil.RemoveFinalizer(vws, finalizerName)
			if err := r.Update(ctx, vws); err != nil {
				return ctrl.Result{}, fmt.Errorf("remove finalizer: %w", err)
			}
		}
		return ctrl.Result{}, nil
	}

	// 3. Add finalizer if absent; return to re-trigger immediately.
	if !controllerutil.ContainsFinalizer(vws, finalizerName) {
		controllerutil.AddFinalizer(vws, finalizerName)
		if err := r.Update(ctx, vws); err != nil {
			return ctrl.Result{}, fmt.Errorf("add finalizer: %w", err)
		}
		return ctrl.Result{}, nil
	}

	// 4. Parse sync interval.
	interval, err := parseSyncInterval(vws.Spec.SyncInterval)
	if err != nil {
		msg := fmt.Sprintf("invalid syncInterval %q: %v", vws.Spec.SyncInterval, err)
		logger.Error(err, "invalid syncInterval", "value", vws.Spec.SyncInterval)
		return r.setFailedStatus(ctx, vws, msg, defaultSyncInterval)
	}

	// 5. Fetch all secrets — fail the whole sync if any key is missing (no partial writes).
	secretData := make(map[string][]byte, len(vws.Spec.Data))
	for _, item := range vws.Spec.Data {
		value, fetchErr := r.VaultClient.GetSecret(item.VaultwardenSecret)
		if fetchErr != nil {
			msg := fmt.Sprintf("failed to fetch Vaultwarden item %q for key %q: %v", item.VaultwardenSecret, item.Key, fetchErr)
			logger.Error(fetchErr, "vault lookup failed", "vaultwardenSecret", item.VaultwardenSecret, "key", item.Key)
			return r.setFailedStatus(ctx, vws, msg, interval)
		}
		secretData[item.Key] = []byte(value)
	}

	// 6. CreateOrUpdate the target Kubernetes Secret using the same name/namespace as the CR.
	secret := &corev1.Secret{}
	secret.Name = vws.Name
	secret.Namespace = vws.Namespace

	op, err := controllerutil.CreateOrUpdate(ctx, r.Client, secret, func() error {
		// Set owner reference for garbage collection.
		if err := controllerutil.SetControllerReference(vws, secret, r.Scheme); err != nil {
			return fmt.Errorf("set controller reference: %w", err)
		}
		if secret.Labels == nil {
			secret.Labels = make(map[string]string)
		}
		secret.Labels["app.kubernetes.io/managed-by"] = managedByLabel
		secret.Type = corev1.SecretTypeOpaque
		secret.Data = secretData
		return nil
	})
	if err != nil {
		msg := fmt.Sprintf("failed to create/update Kubernetes Secret: %v", err)
		logger.Error(err, "createOrUpdate secret failed")
		return r.setFailedStatus(ctx, vws, msg, interval)
	}
	logger.Info("secret reconciled", "operation", op, "secret", types.NamespacedName{Name: secret.Name, Namespace: secret.Namespace})

	// 7. Update status to reflect successful sync.
	now := metav1.Now()
	vws.Status.Ready = true
	vws.Status.LastSyncTime = &now
	vws.Status.LastSyncError = ""
	vws.Status.ObservedGeneration = vws.Generation

	apimeta.SetStatusCondition(&vws.Status.Conditions, metav1.Condition{
		Type:               conditionTypeReady,
		Status:             metav1.ConditionTrue,
		ObservedGeneration: vws.Generation,
		Reason:             "SyncSucceeded",
		Message:            "Vault secrets synced successfully",
	})
	apimeta.RemoveStatusCondition(&vws.Status.Conditions, conditionTypeFailed)

	if err := r.Status().Update(ctx, vws); err != nil {
		return ctrl.Result{}, fmt.Errorf("update status: %w", err)
	}

	// 8. Requeue after interval.
	return ctrl.Result{RequeueAfter: interval}, nil
}

// setFailedStatus updates the CR status to reflect a sync failure and requeues.
func (r *VaultwardenSecretReconciler) setFailedStatus(ctx context.Context, vws *secretsv1alpha1.VaultwardenSecret, msg string, requeueAfter time.Duration) (ctrl.Result, error) {
	vws.Status.Ready = false
	vws.Status.LastSyncError = msg
	vws.Status.ObservedGeneration = vws.Generation

	apimeta.SetStatusCondition(&vws.Status.Conditions, metav1.Condition{
		Type:               conditionTypeReady,
		Status:             metav1.ConditionFalse,
		ObservedGeneration: vws.Generation,
		Reason:             "SyncFailed",
		Message:            msg,
	})
	apimeta.SetStatusCondition(&vws.Status.Conditions, metav1.Condition{
		Type:               conditionTypeFailed,
		Status:             metav1.ConditionTrue,
		ObservedGeneration: vws.Generation,
		Reason:             "SyncFailed",
		Message:            msg,
	})

	if err := r.Status().Update(ctx, vws); err != nil {
		// Log but do not return this error — return the original failure context.
		log.FromContext(ctx).Error(err, "failed to update failed status")
	}

	return ctrl.Result{RequeueAfter: requeueAfter}, nil
}

// parseSyncInterval parses a duration string, defaulting to 5m if empty.
func parseSyncInterval(s string) (time.Duration, error) {
	if s == "" {
		return defaultSyncInterval, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, err
	}
	if d <= 0 {
		return 0, fmt.Errorf("syncInterval must be positive, got %v", d)
	}
	return d, nil
}

// SetupWithManager registers this controller with the manager.
// Owns(&corev1.Secret{}) means external deletion/modification of a managed Secret
// triggers an immediate reconcile to restore desired state.
func (r *VaultwardenSecretReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&secretsv1alpha1.VaultwardenSecret{}).
		Owns(&corev1.Secret{}).
		Complete(r)
}
