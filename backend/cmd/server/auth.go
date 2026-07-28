package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type contextKey string

const userContextKey contextKey = "operator"

type Operator struct {
	ID          string `json:"id"`
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
}

func (a *App) seed(ctx context.Context) error {
	email := strings.ToLower(env("ADMIN_EMAIL", "admin@channel.local"))
	password := env("ADMIN_PASSWORD", "")
	var count int
	if err := a.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM operators`).Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return nil
	}
	if password == "" {
		password = randomToken(12)
		fmt.Printf("初始管理员: %s\n初始管理员密码: %s\n", email, password)
	}
	if len(password) < 10 {
		return fmt.Errorf("ADMIN_PASSWORD 至少需要 10 个字符")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	_, err = a.db.ExecContext(ctx, `INSERT INTO operators(email,password_hash) VALUES($1,$2)`, email, string(hash))
	return err
}

func (a *App) login(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &input); err != nil {
		writeAPIError(w, err)
		return
	}
	var operator Operator
	var passwordHash string
	err := a.db.QueryRowContext(r.Context(), `SELECT id,email,display_name,password_hash FROM operators WHERE email=$1`, strings.ToLower(strings.TrimSpace(input.Email))).Scan(&operator.ID, &operator.Email, &operator.DisplayName, &passwordHash)
	if err != nil || bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(input.Password)) != nil {
		writeAPIError(w, &apiError{Status: 401, Code: "INVALID_CREDENTIALS", Message: "邮箱或密码错误"})
		return
	}
	token := randomToken(32)
	hash := tokenHash(token)
	expiresAt := time.Now().Add(24 * time.Hour)
	_, err = a.db.ExecContext(r.Context(), `INSERT INTO sessions(operator_id,token_hash,expires_at) VALUES($1,$2,$3)`, operator.ID, hash, expiresAt)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	_, _ = a.db.ExecContext(r.Context(), `UPDATE operators SET last_login_at=now() WHERE id=$1`, operator.ID)
	a.audit(context.WithValue(r.Context(), userContextKey, operator), "LOGIN", "operator", operator.ID, map[string]any{"email": operator.Email})
	writeData(w, map[string]any{"access_token": token, "token_type": "Bearer", "expires_at": expiresAt, "operator": operator})
}

func (a *App) authenticate(r *http.Request) (Operator, error) {
	header := strings.TrimSpace(r.Header.Get("Authorization"))
	if !strings.HasPrefix(header, "Bearer ") {
		return Operator{}, fmt.Errorf("missing token")
	}
	token := strings.TrimSpace(strings.TrimPrefix(header, "Bearer "))
	if token == "" {
		return Operator{}, fmt.Errorf("missing token")
	}
	var operator Operator
	err := a.db.QueryRowContext(r.Context(), `
		SELECT o.id,o.email,o.display_name FROM sessions s JOIN operators o ON o.id=s.operator_id
		WHERE s.token_hash=$1 AND s.revoked_at IS NULL AND s.expires_at>now()`, tokenHash(token)).Scan(&operator.ID, &operator.Email, &operator.DisplayName)
	return operator, err
}

func (a *App) logout(w http.ResponseWriter, r *http.Request) error {
	header := strings.TrimSpace(r.Header.Get("Authorization"))
	token := strings.TrimSpace(strings.TrimPrefix(header, "Bearer "))
	_, err := a.db.ExecContext(r.Context(), `UPDATE sessions SET revoked_at=now() WHERE token_hash=$1`, tokenHash(token))
	if err != nil {
		return err
	}
	writeData(w, map[string]bool{"revoked": true})
	return nil
}

func randomToken(bytes int) string {
	buffer := make([]byte, bytes)
	if _, err := io.ReadFull(rand.Reader, buffer); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(buffer)
}

func tokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func deriveCryptoKey(secret string) []byte {
	sum := sha256.Sum256([]byte("channel-manage:credentials:" + secret))
	return sum[:]
}

func (a *App) encryptSecret(plain []byte) ([]byte, error) {
	block, err := aes.NewCipher(a.cryptoKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plain, []byte("channel-manage-v1")), nil
}

func (a *App) decryptSecret(value []byte) ([]byte, error) {
	block, err := aes.NewCipher(a.cryptoKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(value) < gcm.NonceSize() {
		return nil, fmt.Errorf("encrypted value is truncated")
	}
	nonce, ciphertext := value[:gcm.NonceSize()], value[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ciphertext, []byte("channel-manage-v1"))
}

func signValue(secret []byte, value string) string {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(value))
	return hex.EncodeToString(mac.Sum(nil))
}
