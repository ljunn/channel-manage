package main

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	_ "github.com/lib/pq"
)

var (
	Version    = "dev"
	BuildType  = "development"
	GitHubRepo = "ljunn/channel-manage"
)

//go:embed web/dist/*
var embeddedWeb embed.FS

type App struct {
	db                        *sql.DB
	jwtSecret                 []byte
	cryptoKey                 []byte
	web                       http.Handler
	httpClient                *http.Client
	workerMu                  sync.Mutex
	recoveryMu                sync.Mutex
	policyEvaluationMu        sync.Mutex
	policyEvaluationRunning   bool
	policyEvaluationRequested bool
	policyEvidenceBaselineAt  time.Time
	mappingMu                 sync.RWMutex
	mappingGroupLocks         sync.Map
	sourceAuthLocks           sync.Map
	sourceTokenRefreshMu      sync.Mutex
	targetAuthMu              sync.Mutex
	targetAssetLocks          sync.Map
	targetMultiplierMu        sync.Mutex
	targetMultiplierRefreshes map[string]struct{}
	targetPlatformMu          sync.Mutex
	targetPlatformSyncs       map[string]struct{}
	targetModelMu             sync.Mutex
	targetModelSyncs          map[string]struct{}
	targetRateMu              sync.Mutex
	targetRateSyncs           map[string]struct{}
	targetSchedulableMu       sync.Mutex
	targetSchedulableSyncs    map[string]struct{}
	managedActionLocksMu      sync.Mutex
	managedActionLocks        map[string]*sync.Mutex
	quickValidationMu         sync.Mutex
	quickValidations          map[string]struct{}
	modelQualityMu            sync.Mutex
	modelQualityRunning       map[string]struct{}
	modelQualitySlots         chan struct{}
}

type apiError struct {
	Status  int
	Code    string
	Message string
}

func (e *apiError) Error() string {
	if e.Message == "" {
		return e.Code
	}
	if e.Code == "" {
		return e.Message
	}
	return e.Code + ": " + e.Message
}

func userErrorMessage(err error) string {
	var typed *apiError
	if errors.As(err, &typed) && typed.Message != "" {
		return typed.Message
	}
	if err == nil {
		return ""
	}
	return err.Error()
}

func main() {
	ctx := context.Background()
	db, err := sql.Open("postgres", databaseURL())
	if err != nil {
		log.Fatalf("打开数据库失败: %v", err)
	}
	db.SetMaxOpenConns(envInt("DATABASE_MAX_OPEN_CONNS", 30))
	db.SetMaxIdleConns(envInt("DATABASE_MAX_IDLE_CONNS", 10))
	if err := waitDB(ctx, db, 60*time.Second); err != nil {
		log.Fatalf("连接数据库失败: %v", err)
	}
	if err := migrate(ctx, db); err != nil {
		log.Fatalf("初始化数据库失败: %v", err)
	}
	secret := env("JWT_SECRET", "")
	if len(secret) < 32 {
		log.Fatal("JWT_SECRET 至少需要 32 个字符")
	}
	webRoot, _ := fs.Sub(embeddedWeb, "web/dist")
	app := &App{
		db:                       db,
		jwtSecret:                []byte(secret),
		cryptoKey:                deriveCryptoKey(env("CREDENTIAL_ENCRYPTION_KEY", secret)),
		web:                      http.FileServer(http.FS(webRoot)),
		httpClient:               newRemoteHTTPClient(),
		policyEvidenceBaselineAt: time.Now(),
	}
	if err := app.seed(ctx); err != nil {
		log.Fatalf("初始化管理员失败: %v", err)
	}
	// Drain only durable, never-started new-channel checks. Completed checks and
	// technical UNKNOWN results are intentionally left for an operator to rerun.
	app.queuePendingModelChecks(ctx)

	server := &http.Server{
		Addr:              env("SERVER_HOST", "0.0.0.0") + ":" + env("SERVER_PORT", "8080"),
		Handler:           app,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       90 * time.Second,
	}
	workerCtx, stopWorker := context.WithCancel(context.Background())
	go app.runScheduler(workerCtx)
	go func() {
		log.Printf("渠道管家 %s 启动: http://%s", Version, server.Addr)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("服务异常退出: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	stopWorker()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = server.Shutdown(shutdownCtx)
	_ = db.Close()
}

func (a *App) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w)
	if r.URL.Path == "/health" {
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "service": "channel-manage", "version": Version})
		return
	}
	if strings.HasPrefix(r.URL.Path, "/api/") {
		a.serveAPI(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	request := r.Clone(r.Context())
	if request.URL.Path == "/" || !strings.Contains(request.URL.Path, ".") {
		request.URL.Path = "/"
	}
	a.web.ServeHTTP(w, request)
}

func (a *App) serveAPI(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if path == "/auth/login" && r.Method == http.MethodPost {
		a.login(w, r)
		return
	}
	user, err := a.authenticate(r)
	if err != nil {
		writeAPIError(w, &apiError{Status: 401, Code: "UNAUTHORIZED", Message: "请先登录"})
		return
	}
	r = r.WithContext(context.WithValue(r.Context(), userContextKey, user))
	if err := a.routeAPI(w, r, path); err != nil {
		writeAPIError(w, err)
	}
}

func decodeJSON(r *http.Request, target any) error {
	decoder := json.NewDecoder(io.LimitReader(r.Body, 2<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return &apiError{Status: 400, Code: "INVALID_JSON", Message: "请求内容不是有效 JSON"}
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeData(w http.ResponseWriter, value any) {
	writeJSON(w, http.StatusOK, map[string]any{"data": value})
}

func writeAPIError(w http.ResponseWriter, err error) {
	var typed *apiError
	if !errors.As(err, &typed) {
		log.Printf("API error: %v", err)
		typed = &apiError{Status: 500, Code: "INTERNAL_ERROR", Message: "服务处理失败，请查看日志"}
	}
	writeJSON(w, typed.Status, map[string]any{"error": map[string]string{"code": typed.Code, "message": typed.Message}})
}

func setSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "same-origin")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'")
}

func databaseURL() string {
	if value := os.Getenv("DATABASE_URL"); value != "" {
		return value
	}
	return fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		env("DATABASE_HOST", "localhost"), env("DATABASE_PORT", "5432"),
		env("DATABASE_USER", "channel_manage"), env("DATABASE_PASSWORD", "channel_manage_password"),
		env("DATABASE_DBNAME", "channel_manage"), env("DATABASE_SSLMODE", "disable"))
}

func env(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func envInt(name string, fallback int) int {
	value, err := strconv.Atoi(env(name, strconv.Itoa(fallback)))
	if err != nil {
		return fallback
	}
	return value
}

func envBool(name string, fallback bool) bool {
	value, err := strconv.ParseBool(env(name, strconv.FormatBool(fallback)))
	if err != nil {
		return fallback
	}
	return value
}

func waitDB(ctx context.Context, db *sql.DB, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		if err := db.PingContext(ctx); err == nil {
			return nil
		} else if time.Now().After(deadline) {
			return err
		}
		time.Sleep(time.Second)
	}
}
