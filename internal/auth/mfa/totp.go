package mfa

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"image/png"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	"github.com/lusopoint/lusoiam/internal/store/postgres"
)

// TOTPSecret is what the enrollment UI needs to display data:image/png QR code (for scanning)
type TOTPSecret struct {
	MethodID   pgtype.UUID
	Base32     string // the shared secret
	OTPAuthURL string // otpauth://totp/Issuer:account?secret=...
	QRCodeData string // data:image/png;base64,... for <img src=...>
}

// totpDigits 6 digits is the universal default
const totpDigits = otp.DigitsSix

// totpPeriod 30 seconds is the RFC 6238 default
const totpPeriod = uint(30)

// BeginTOTPEnrollment generates a new TOTP secret for the user and
// persists an unconfirmed row, the user must verify a generated code
// to call ConfirmTOTPEnrollment, which marks the method usable
func (s *Service) BeginTOTPEnrollment(ctx context.Context, userID pgtype.UUID, accountLabel, label string) (*TOTPSecret, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      s.totpIssuer,
		AccountName: accountLabel,
		Period:      totpPeriod,
		Digits:      totpDigits,
		Algorithm:   otp.AlgorithmSHA1, // most-compatible; Google Auth, 1Password, etc.
	})
	if err != nil {
		return nil, fmt.Errorf("generate totp key: %w", err)
	}

	// render the QR as an inline PNG data URL, avoids an extra request
	// and works without any QR library
	img, err := key.Image(240, 240)
	if err != nil {
		return nil, fmt.Errorf("render qr image: %w", err)
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, fmt.Errorf("encode qr png: %w", err)
	}
	dataURL := "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes())

	var name *string
	if label != "" {
		name = &label
	}

	method, err := s.store.CreateTOTPMethod(ctx, postgres.CreateTOTPMethodParams{
		UserID: userID,
		Name:   name,
		Secret: key.Secret(),
	})
	if err != nil {
		return nil, fmt.Errorf("persist totp method: %w", err)
	}

	return &TOTPSecret{
		MethodID:   method.ID,
		Base32:     key.Secret(),
		OTPAuthURL: key.URL(),
		QRCodeData: dataURL,
	}, nil
}

// ConfirmTOTPEnrollment verifies code against the secret stored on the
// given unconfirmed method and, on success, marks the method confirmed
// once confirmed, the method counts toward the users MFA requirement
func (s *Service) ConfirmTOTPEnrollment(ctx context.Context, methodID pgtype.UUID, code string) error {
	method, err := s.store.GetMFAMethod(ctx, methodID)
	if err != nil {
		return err
	}
	if method.Method != "totp" || method.Secret == nil {
		return errors.New("mfa: method is not a pending TOTP enrollment")
	}
	if method.ConfirmedAt != nil {
		return errors.New("mfa: method already confirmed")
	}

	if !totp.Validate(code, *method.Secret) {
		return ErrInvalidCode
	}
	if err := s.store.ConfirmMFAMethod(ctx, methodID); err != nil {
		return fmt.Errorf("confirm method: %w", err)
	}
	return nil
}

// VerifyTOTP is called during a login challenge, it walks every confirmed TOTP
// method for the user and accepts on the first match
// on success, returns the method id used so we can bump last_used_at
//
// the single-validation-step is intentional: TOTP codes are short
// (1M possibilities) so we apply an aggressive per-challenge attempt
// limit higher up the stack (in the http handler) rather than trying
// to track per-method failures here
func (s *Service) VerifyTOTP(ctx context.Context, userID pgtype.UUID, code string) (*postgres.UserMFAMethod, error) {
	methods, err := s.store.ListConfirmedMFAMethods(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("list methods: %w", err)
	}
	for i := range methods {
		m := &methods[i]
		if m.Method != "totp" || m.Secret == nil {
			continue
		}
		valid, err := totp.ValidateCustom(code, *m.Secret, time.Now(), totp.ValidateOpts{
			Period:    totpPeriod,
			Skew:      1, // accept the previous & next 30-second window
			Digits:    totpDigits,
			Algorithm: otp.AlgorithmSHA1,
		})
		if err != nil {
			// malformed code or secret, treat as a verification failure not a system error
			continue
		}
		if valid {
			_ = s.store.TouchMFAMethodUsage(ctx, m.ID)
			return m, nil
		}
	}
	return nil, ErrInvalidCode
}
