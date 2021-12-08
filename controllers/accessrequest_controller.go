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

package controllers

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"golang.org/x/crypto/ssh"
	"io"
	mrand "math/rand"
	"time"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apiErrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	crv1beta1 "mkgrei/requests-poc/api/v1beta1"
)

// AccessRequestReconciler reconciles a AccessRequest object
type AccessRequestReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

const (
	defaultNamespace   = "default"
	defaultRoleBinding = "pod-viewer"
	controllerKey      = "controller"
	controllerVal      = "AccessRequest"
)

var (
	defaultVerb = [...]string{"get", "list", "watch"}
	letters     = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
)

//+kubebuilder:rbac:groups=cr.requests.test,resources=accessrequests,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=cr.requests.test,resources=accessrequests/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=cr.requests.test,resources=accessrequests/finalizers,verbs=update
//+kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=role,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=rolebinding,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=,resources=serviceaccount,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=,resources=secret,verbs=get;list;watch;create;update;patch;delete

// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.10.0/pkg/reconcile
func (r *AccessRequestReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	l := log.FromContext(ctx)

	var (
		err   error
		ca    string
		token string
		obj   crv1beta1.AccessRequest
		sa    *corev1.ServiceAccount
		sec   corev1.Secret
	)

	if err = r.Get(ctx, req.NamespacedName, &obj); err != nil {
		if apiErrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		l.Info(err.Error())
		return ctrl.Result{}, err
	}

	if !obj.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil
	}

	if a := obj.Status.Accepted; !a {
		fmt.Println("not accepteed")
		return ctrl.Result{}, nil
	}

	sa, _, err = r.reconcileServiceAccount(ctx, &obj)
	if len(sa.Secrets) == 0 {
		return ctrl.Result{RequeueAfter: time.Second * 2}, nil
	}
	sec = corev1.Secret{}
	sec.Name = sa.Secrets[0].Name
	sec.Namespace = sa.Namespace

	if err = r.Get(ctx, client.ObjectKeyFromObject(&sec), &sec); err != nil {
		return ctrl.Result{}, err
	}

	key := generateKey(32)
	ekey, err := encryptRSA(obj.Spec.PubKey, []byte(key))
	ca, err = encryptAES(key, sec.Data["ca.crt"])
	if err != nil {
		return ctrl.Result{}, err
	}
	token, err = encryptAES(key, sec.Data["token"])
	if err != nil {
		return ctrl.Result{}, err
	}
	obj.Status.CA = ca
	obj.Status.Key = ekey
	obj.Status.Token = token
	obj.Status.Ready = true
	err = r.Status().Update(ctx, &obj)
	if err != nil {
		return ctrl.Result{}, err
	}

	if err = r.reconcileRoleBinding(ctx, &obj); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

func (r *AccessRequestReconciler) reconcileServiceAccount(ctx context.Context, req *crv1beta1.AccessRequest) (*corev1.ServiceAccount, bool, error) {
	var (
		err error
	)
	sa := corev1.ServiceAccount{}
	sa.Name = req.Name
	sa.Namespace = defaultNamespace
	if err = r.Get(ctx, client.ObjectKeyFromObject(&sa), &sa); err != nil {
		if client.IgnoreNotFound(err) != nil {
			return nil, false, err
		}
		sa.Annotations = map[string]string{controllerKey: controllerVal}
		if err = r.Create(ctx, &sa); err != nil {
			return nil, false, err
		}
		return &sa, true, nil
	}

	cn, found := sa.Annotations[controllerKey]
	if !found {
		return nil, false, errors.New("ServiceAccount is not under control")
	}
	if cn != controllerVal {
		return nil, false, errors.New("ServiceAccount has other controller")
	}
	return &sa, false, nil
}

func (r *AccessRequestReconciler) reconcileRoleBinding(ctx context.Context, req *crv1beta1.AccessRequest) error {
	var err error
	rb := rbacv1.RoleBinding{}
	rb.Name = defaultRoleBinding
	rb.Namespace = defaultNamespace
	if err = r.Get(ctx, client.ObjectKeyFromObject(&rb), &rb); err != nil {
		return err
	}

	s := rbacv1.Subject{
		Kind:      "ServiceAccount",
		Namespace: defaultNamespace,
		Name:      req.Name,
	}
	if !contains(rb.Subjects, s) {
		rb.Subjects = append(rb.Subjects, s)
	}

	if err = r.Update(ctx, &rb); err != nil {
		return err
	}
	return nil
}

func contains(ss []rbacv1.Subject, s rbacv1.Subject) bool {
	for _, cs := range ss {
		if cs.Kind == s.Kind &&
			cs.Name == s.Name &&
			cs.Namespace == s.Namespace {
			return true
		}
	}
	return false
}

func encryptRSA(k string, s []byte) (string, error) {
	pkey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(k))
	if err != nil {
		return "", err
	}
	pckey := pkey.(ssh.CryptoPublicKey)
	prkey := pckey.CryptoPublicKey().(*rsa.PublicKey)
	enc, err := rsa.EncryptOAEP(sha512.New(), crand.Reader, prkey, s, nil)
	if err != nil {
		return "", err
	}
	emsg := base64.StdEncoding.EncodeToString(enc)
	return emsg, nil
}

func encryptAES(k string, s []byte) (string, error) {
	c, err := aes.NewCipher([]byte(k))
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())

	if _, err = io.ReadFull(crand.Reader, nonce); err != nil {
		return "", err
	}

	enc := gcm.Seal(nonce, nonce, s, nil)
	emsg := base64.StdEncoding.EncodeToString(enc)
	return emsg, nil
}

func generateKey(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[mrand.Intn(len(letters))]
	}
	return string(b)
}

// SetupWithManager sets up the controller with the Manager.
func (r *AccessRequestReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&crv1beta1.AccessRequest{}).
		Owns(&corev1.ServiceAccount{}).
		Complete(r)
}
