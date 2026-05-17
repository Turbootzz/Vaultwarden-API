// Package main is the entrypoint for the Vaultwarden Kubernetes operator.
package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	secretsv1alpha1 "github.com/Turbootzz/vaultwarden-api/internal/operator/api/v1alpha1"
	"github.com/Turbootzz/vaultwarden-api/internal/operator/controller"
	"github.com/Turbootzz/vaultwarden-api/internal/vaultwarden"
)

var scheme = runtime.NewScheme()

func init() {
	_ = clientgoscheme.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)
	_ = secretsv1alpha1.AddToScheme(scheme)
}

func main() {
	var metricsAddr string
	var probeAddr string
	var leaderElect bool
	var leaderElectNamespace string

	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "The address the metric endpoint binds to.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&leaderElect, "leader-elect", false, "Enable leader election for controller manager.")
	flag.StringVar(&leaderElectNamespace, "leader-elect-namespace", "", "Namespace for leader election. Defaults to operator namespace.")
	flag.Parse()

	// Environment overrides for leader election (useful in Kubernetes deployments).
	if v := os.Getenv("LEADER_ELECT"); v == "true" {
		leaderElect = true
	}
	if v := os.Getenv("LEADER_ELECT_NAMESPACE"); v != "" {
		leaderElectNamespace = v
	}

	opts := zap.Options{Development: false}
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))
	setupLog := ctrl.Log.WithName("setup")

	// Read required Vaultwarden env vars.
	vaultURL := requireEnv("VAULTWARDEN_URL")
	vaultEmail := requireEnv("VAULTWARDEN_EMAIL")
	vaultPassword := requireEnv("VAULTWARDEN_PASSWORD")

	// Optional env vars.
	clientID := os.Getenv("VAULTWARDEN_CLIENT_ID")
	clientSecret := os.Getenv("VAULTWARDEN_CLIENT_SECRET")

	cacheTTL := parseDurationEnv("CACHE_TTL", 5*time.Minute)
	syncInterval := parseDurationEnv("SYNC_INTERVAL", 5*time.Minute)

	// Initialize the Vaultwarden client (3-attempt retry with exponential backoff).
	setupLog.Info("Initializing Vaultwarden client...")
	vaultClient, err := vaultwarden.InitializeClient(vaultURL, vaultEmail, vaultPassword, clientID, clientSecret, cacheTTL, syncInterval)
	if err != nil {
		setupLog.Error(err, "Failed to initialize Vaultwarden client")
		os.Exit(1)
	}
	defer vaultClient.Stop()
	setupLog.Info("Vaultwarden client initialized")

	// Set up the controller manager.
	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme: scheme,
		Metrics: metricsserver.Options{
			BindAddress: metricsAddr,
		},
		HealthProbeBindAddress:        probeAddr,
		LeaderElection:                leaderElect,
		LeaderElectionID:              "vaultwarden-operator-leader",
		LeaderElectionNamespace:       leaderElectNamespace,
		LeaderElectionReleaseOnCancel: true,
	})
	if err != nil {
		setupLog.Error(err, "unable to create manager")
		os.Exit(1)
	}

	// Register the reconciler.
	if err = (&controller.VaultwardenSecretReconciler{
		Client:      mgr.GetClient(),
		Scheme:      mgr.GetScheme(),
		VaultClient: vaultClient,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "VaultwardenSecret")
		os.Exit(1)
	}

	// Health and readiness probes.
	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("Starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}

// requireEnv reads a required environment variable or exits.
func requireEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		fmt.Fprintf(os.Stderr, "fatal: required environment variable %s is not set\n", key)
		os.Exit(1)
	}
	return v
}

// parseDurationEnv reads an optional duration env var with a fallback default.
func parseDurationEnv(key string, fallback time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		ctrl.Log.WithName("setup").Info("Invalid duration env var, using default", "key", key, "value", v, "default", fallback)
		return fallback
	}
	return d
}
