package main

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

const maxUpdateDownload = 256 << 20

var (
	updateCheckMu sync.Mutex
	updateCache   *releaseUpdateInfo
	updateCacheAt time.Time
	updateMu      sync.Mutex
)

type githubReleaseAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

type githubRelease struct {
	TagName     string               `json:"tag_name"`
	Name        string               `json:"name"`
	Body        string               `json:"body"`
	HTMLURL     string               `json:"html_url"`
	PublishedAt string               `json:"published_at"`
	Draft       bool                 `json:"draft"`
	Prerelease  bool                 `json:"prerelease"`
	Assets      []githubReleaseAsset `json:"assets"`
}

type releaseUpdateInfo struct {
	CurrentVersion string `json:"currentVersion"`
	LatestVersion  string `json:"latestVersion"`
	HasUpdate      bool   `json:"hasUpdate"`
	Name           string `json:"name"`
	Body           string `json:"body"`
	HTMLURL        string `json:"htmlUrl"`
	PublishedAt    string `json:"publishedAt"`
	Cached         bool   `json:"cached"`
	ArchiveURL     string `json:"-"`
	ChecksumURL    string `json:"-"`
}

func configuredUpdateRepo() string { return env("UPDATE_GITHUB_REPO", GitHubRepo) }

func validRepository(value string) bool {
	parts := strings.Split(value, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return false
	}
	for _, part := range parts {
		for _, char := range part {
			if !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || strings.ContainsRune("-_.", char)) {
				return false
			}
		}
	}
	return true
}

func updateSupported() bool { return BuildType == "release" && validRepository(configuredUpdateRepo()) }

func executablePath() string {
	path, err := os.Executable()
	if err != nil {
		return ""
	}
	if resolved, resolveErr := filepath.EvalSymlinks(path); resolveErr == nil {
		return resolved
	}
	return path
}

func updateSystemInfo() map[string]any {
	executable := executablePath()
	_, rollbackErr := os.Stat(executable + ".backup")
	pendingVersion := ""
	if content, err := os.ReadFile(executable + ".pending"); err == nil {
		pendingVersion = strings.TrimSpace(string(content))
		if compareReleaseVersions(Version, pendingVersion) == 0 {
			_ = os.Remove(executable + ".pending")
			pendingVersion = ""
		}
	}
	return map[string]any{"currentVersion": strings.TrimPrefix(Version, "v"), "buildType": BuildType, "repository": configuredUpdateRepo(), "updateSupported": updateSupported(), "restartSupported": env("DEPLOYMENT_MODE", "docker") == "docker", "rollbackAvailable": rollbackErr == nil, "restartPending": pendingVersion != "", "pendingVersion": pendingVersion}
}

func (a *App) checkSystemUpdate(ctx context.Context, force bool) (releaseUpdateInfo, error) {
	if !updateSupported() {
		return releaseUpdateInfo{}, &apiError{409, "UPDATE_UNSUPPORTED", "当前不是正式发布构建，无法在线更新"}
	}
	updateCheckMu.Lock()
	defer updateCheckMu.Unlock()
	if !force && updateCache != nil && time.Since(updateCacheAt) < 20*time.Minute {
		result := *updateCache
		result.Cached = true
		return result, nil
	}
	var release githubRelease
	if err := githubUpdateJSON(ctx, "https://api.github.com/repos/"+configuredUpdateRepo()+"/releases/latest", &release); err != nil {
		return releaseUpdateInfo{}, err
	}
	if release.Draft || release.Prerelease {
		return releaseUpdateInfo{}, &apiError{502, "UPDATE_RELEASE_INVALID", "最新发布不是稳定版本"}
	}
	latest := strings.TrimPrefix(release.TagName, "v")
	archiveName := fmt.Sprintf("channel-manage_%s_%s_%s.tar.gz", latest, runtime.GOOS, runtime.GOARCH)
	info := releaseUpdateInfo{CurrentVersion: strings.TrimPrefix(Version, "v"), LatestVersion: latest, HasUpdate: compareReleaseVersions(Version, latest) < 0, Name: release.Name, Body: release.Body, HTMLURL: release.HTMLURL, PublishedAt: release.PublishedAt}
	for _, asset := range release.Assets {
		if asset.Name == archiveName {
			info.ArchiveURL = asset.BrowserDownloadURL
		}
		if asset.Name == "checksums.txt" {
			info.ChecksumURL = asset.BrowserDownloadURL
		}
	}
	copy := info
	updateCache, updateCacheAt = &copy, time.Now()
	return info, nil
}

func githubUpdateJSON(ctx context.Context, endpoint string, target any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "channel-manage-updater/"+Version)
	if token := env("UPDATE_GITHUB_TOKEN", ""); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return &apiError{502, "UPDATE_CHECK_FAILED", "无法连接 GitHub 检查更新"}
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return &apiError{502, "UPDATE_CHECK_FAILED", fmt.Sprintf("GitHub 返回 HTTP %d", response.StatusCode)}
	}
	if err = json.NewDecoder(io.LimitReader(response.Body, 4<<20)).Decode(target); err != nil {
		return &apiError{502, "UPDATE_CHECK_FAILED", "GitHub 发布信息格式无效"}
	}
	return nil
}

func (a *App) performSystemUpdate(ctx context.Context) (map[string]any, error) {
	if !updateMu.TryLock() {
		return nil, &apiError{409, "UPDATE_BUSY", "另一个更新或回滚操作正在进行"}
	}
	defer updateMu.Unlock()
	updateCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Minute)
	defer cancel()
	info, err := a.checkSystemUpdate(updateCtx, true)
	if err != nil {
		return nil, err
	}
	if !info.HasUpdate {
		return map[string]any{"alreadyUpToDate": true, "currentVersion": info.CurrentVersion}, nil
	}
	if info.ArchiveURL == "" || info.ChecksumURL == "" {
		return nil, &apiError{502, "UPDATE_ASSET_MISSING", "发布缺少当前系统架构文件或 checksums.txt"}
	}
	if err = applyReleaseBinary(updateCtx, info); err != nil {
		return nil, err
	}
	return map[string]any{"updated": true, "version": info.LatestVersion, "needRestart": true}, nil
}

func applyReleaseBinary(ctx context.Context, info releaseUpdateInfo) error {
	if err := validateReleaseURL(info.ArchiveURL); err != nil {
		return err
	}
	if err := validateReleaseURL(info.ChecksumURL); err != nil {
		return err
	}
	executable := executablePath()
	if executable == "" {
		return &apiError{500, "UPDATE_PATH_UNKNOWN", "无法确定当前程序路径"}
	}
	tempDir, err := os.MkdirTemp(filepath.Dir(executable), ".channel-manage-update-")
	if err != nil {
		return &apiError{500, "UPDATE_PATH_READONLY", "程序目录不可写，无法安装更新"}
	}
	defer os.RemoveAll(tempDir)
	archive, checksums := filepath.Join(tempDir, "release.tar.gz"), filepath.Join(tempDir, "checksums.txt")
	if err = downloadUpdateFile(ctx, info.ArchiveURL, archive, maxUpdateDownload); err != nil {
		return err
	}
	if err = downloadUpdateFile(ctx, info.ChecksumURL, checksums, 2<<20); err != nil {
		return err
	}
	if err = verifyUpdateChecksum(archive, checksums, filepath.Base(info.ArchiveURL)); err != nil {
		return err
	}
	newBinary := filepath.Join(tempDir, "channel-manage")
	if err = extractUpdateBinary(archive, newBinary); err != nil {
		return err
	}
	if err = os.Chmod(newBinary, 0755); err != nil {
		return err
	}
	backup := executable + ".backup"
	_ = os.Remove(backup)
	if err = os.Rename(executable, backup); err != nil {
		return &apiError{500, "UPDATE_BACKUP_FAILED", "备份当前版本失败"}
	}
	if err = os.Rename(newBinary, executable); err != nil {
		_ = os.Rename(backup, executable)
		return &apiError{500, "UPDATE_REPLACE_FAILED", "替换程序失败，已恢复原版本"}
	}
	_ = os.WriteFile(executable+".pending", []byte(info.LatestVersion+"\n"), 0600)
	return nil
}

func validateReleaseURL(value string) error {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" {
		return &apiError{502, "UPDATE_URL_INVALID", "发布下载地址必须使用 HTTPS"}
	}
	host := strings.ToLower(parsed.Hostname())
	if host != "github.com" && host != "objects.githubusercontent.com" && !strings.HasSuffix(host, ".githubusercontent.com") {
		return &apiError{502, "UPDATE_URL_UNTRUSTED", "发布下载地址不受信任"}
	}
	return nil
}

func downloadUpdateFile(ctx context.Context, source, destination string, limit int64) error {
	client := &http.Client{Timeout: 10 * time.Minute, CheckRedirect: func(req *http.Request, _ []*http.Request) error { return validateReleaseURL(req.URL.String()) }}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "channel-manage-updater/"+Version)
	if token := env("UPDATE_GITHUB_TOKEN", ""); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := client.Do(req)
	if err != nil {
		return &apiError{502, "UPDATE_DOWNLOAD_FAILED", "下载更新失败"}
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 || response.ContentLength > limit {
		return &apiError{502, "UPDATE_DOWNLOAD_FAILED", fmt.Sprintf("下载更新返回 HTTP %d", response.StatusCode)}
	}
	file, err := os.Create(destination)
	if err != nil {
		return err
	}
	defer file.Close()
	written, err := io.Copy(file, io.LimitReader(response.Body, limit+1))
	if err != nil || written > limit {
		return &apiError{502, "UPDATE_DOWNLOAD_FAILED", "更新文件下载不完整或超过大小限制"}
	}
	return nil
}

func verifyUpdateChecksum(archive, checksums, assetName string) error {
	content, err := os.ReadFile(checksums)
	if err != nil {
		return err
	}
	expected := ""
	for _, line := range strings.Split(string(content), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && strings.TrimPrefix(fields[1], "*") == assetName {
			expected = strings.ToLower(fields[0])
		}
	}
	if expected == "" {
		return &apiError{502, "UPDATE_CHECKSUM_MISSING", "校验文件中没有当前更新包"}
	}
	file, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err = io.Copy(hash, file); err != nil || hex.EncodeToString(hash.Sum(nil)) != expected {
		return &apiError{502, "UPDATE_CHECKSUM_FAILED", "更新包 SHA-256 校验失败"}
	}
	return nil
}

func extractUpdateBinary(archive, destination string) error {
	file, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer file.Close()
	gz, err := gzip.NewReader(file)
	if err != nil {
		return err
	}
	defer gz.Close()
	reader := tar.NewReader(gz)
	for {
		header, nextErr := reader.Next()
		if nextErr == io.EOF {
			break
		}
		if nextErr != nil {
			return nextErr
		}
		if header.Typeflag != tar.TypeReg || filepath.Base(header.Name) != "channel-manage" || strings.Contains(header.Name, "..") {
			continue
		}
		if header.Size <= 0 || header.Size > maxUpdateDownload {
			return &apiError{502, "UPDATE_BINARY_INVALID", "更新包中的程序文件大小无效"}
		}
		output, createErr := os.Create(destination)
		if createErr != nil {
			return createErr
		}
		written, copyErr := io.Copy(output, io.LimitReader(reader, header.Size))
		closeErr := output.Close()
		if copyErr != nil || written != header.Size {
			_ = os.Remove(destination)
			if copyErr == nil {
				return &apiError{502, "UPDATE_BINARY_INVALID", "更新包中的程序文件不完整"}
			}
			return copyErr
		}
		return closeErr
	}
	return &apiError{502, "UPDATE_BINARY_MISSING", "更新包中没有 channel-manage 程序"}
}

func rollbackSystemUpdate() error {
	if !updateMu.TryLock() {
		return &apiError{409, "UPDATE_BUSY", "另一个更新或回滚操作正在进行"}
	}
	defer updateMu.Unlock()
	executable := executablePath()
	backup := executable + ".backup"
	if executable == "" {
		return errors.New("无法确定当前程序路径")
	}
	if _, err := os.Stat(backup); err != nil {
		return &apiError{409, "ROLLBACK_UNAVAILABLE", "没有可回滚的本地备份"}
	}
	current := executable + ".rollback"
	_ = os.Remove(current)
	if err := os.Rename(executable, current); err != nil {
		return err
	}
	if err := os.Rename(backup, executable); err != nil {
		_ = os.Rename(current, executable)
		return &apiError{500, "ROLLBACK_FAILED", "回滚失败，已恢复当前版本"}
	}
	_ = os.Remove(executable + ".pending")
	return nil
}

func restartSystem() {
	go func() { time.Sleep(800 * time.Millisecond); os.Exit(0) }()
}

func compareReleaseVersions(left, right string) int {
	parse := func(value string) [3]int {
		var result [3]int
		for index, part := range strings.Split(strings.TrimPrefix(value, "v"), ".") {
			if index >= 3 {
				break
			}
			if at := strings.IndexAny(part, "-+"); at >= 0 {
				part = part[:at]
			}
			result[index], _ = strconv.Atoi(part)
		}
		return result
	}
	a, b := parse(left), parse(right)
	for index := range a {
		if a[index] < b[index] {
			return -1
		}
		if a[index] > b[index] {
			return 1
		}
	}
	return 0
}
