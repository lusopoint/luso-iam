package mfa

import (
	"reflect"
	"testing"
)

// TestComputeStatus_Matrix pins the policy. Four input dimensions
// (enrolled / not enrolled, with backup codes / without, force MFA on
// / off) produce a Status with Required + EnrollmentRequired flags
// downstream code branches on. The matrix is the test.
func TestComputeStatus_Matrix(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name          string
		methods       []string
		hasBackup     bool
		forceMFA      bool
		wantRequired  bool
		wantEnrollReq bool
	}{
		// ── ForceMFA disabled (default posture) ────────────────────────
		// No enrollment → MFA is just not required. Login proceeds with
		// password alone.
		{
			name:          "force_off_no_methods",
			methods:       nil,
			forceMFA:      false,
			wantRequired:  false,
			wantEnrollReq: false,
		},
		// Enrolled → MFA required, no enrollment forcing. Existing
		// "opt-in MFA per user" behaviour.
		{
			name:          "force_off_with_totp",
			methods:       []string{"totp"},
			forceMFA:      false,
			wantRequired:  true,
			wantEnrollReq: false,
		},
		{
			name:          "force_off_with_webauthn",
			methods:       []string{"webauthn"},
			forceMFA:      false,
			wantRequired:  true,
			wantEnrollReq: false,
		},
		{
			name:          "force_off_with_multiple",
			methods:       []string{"totp", "webauthn"},
			forceMFA:      false,
			wantRequired:  true,
			wantEnrollReq: false,
		},

		// ── ForceMFA enabled ──────────────────────────────────────────
		// Enrolled → behaves identically to opt-in: required, no enroll.
		// The user has a method; they'll be challenged.
		{
			name:          "force_on_with_totp",
			methods:       []string{"totp"},
			forceMFA:      true,
			wantRequired:  true,
			wantEnrollReq: false,
		},
		// THE interesting case: ForceMFA on, no enrolled methods. This
		// is the only path that sets EnrollmentRequired. Caller MUST
		// bounce the user to /mfa/enroll instead of /mfa challenge.
		{
			name:          "force_on_no_methods",
			methods:       nil,
			forceMFA:      true,
			wantRequired:  true,
			wantEnrollReq: true,
		},
		// Edge: an empty (non-nil) slice should behave identically to nil.
		{
			name:          "force_on_empty_methods_slice",
			methods:       []string{},
			forceMFA:      true,
			wantRequired:  true,
			wantEnrollReq: true,
		},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			got := computeStatus(c.methods, c.hasBackup, c.forceMFA)
			if got.Required != c.wantRequired {
				t.Errorf("Required = %v, want %v", got.Required, c.wantRequired)
			}
			if got.EnrollmentRequired != c.wantEnrollReq {
				t.Errorf("EnrollmentRequired = %v, want %v", got.EnrollmentRequired, c.wantEnrollReq)
			}
			// MethodTypes and HasBackupCodes pass through unchanged
			// pin those too as a sanity check.
			if !reflect.DeepEqual(got.MethodTypes, c.methods) {
				t.Errorf("MethodTypes = %v, want %v", got.MethodTypes, c.methods)
			}
			if got.HasBackupCodes != c.hasBackup {
				t.Errorf("HasBackupCodes = %v, want %v", got.HasBackupCodes, c.hasBackup)
			}
		})
	}
}

// TestComputeStatus_Invariant: EnrollmentRequired implies Required.
// Caller code branches on EnrollmentRequired assuming Required is true;
// if this invariant ever broke, downstream gating would silently miss
// the enrollment redirect.
func TestComputeStatus_Invariant(t *testing.T) {
	t.Parallel()
	for _, force := range []bool{false, true} {
		for _, methods := range [][]string{nil, {"totp"}, {"webauthn"}, {"totp", "webauthn"}} {
			s := computeStatus(methods, false, force)
			if s.EnrollmentRequired && !s.Required {
				t.Errorf("invariant broken: EnrollmentRequired=true but Required=false (force=%v methods=%v)", force, methods)
			}
		}
	}
}
