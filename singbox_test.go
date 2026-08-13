package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestCompareSingBoxVersion(t *testing.T) {
	min, _ := parseSingBoxVersion("sing-box version " + singBoxMinVersion)
	tests := []struct {
		version string
		want    int
	}{
		{"1.13.9", -1},
		{"1.14.0-alpha.49", -1},
		{"1.14.0-alpha.50", 0},
		{"1.14.0-alpha.51", 1},
		{"1.14.1", 1},
		{"1.15.0", 1},
	}
	for _, tc := range tests {
		got, ok := parseSingBoxVersion("sing-box version " + tc.version)
		if !ok {
			t.Fatalf("parse %s failed", tc.version)
		}
		cmp := compareSingBoxVersion(got, min)
		if (cmp < 0 && tc.want >= 0) || (cmp == 0 && tc.want != 0) || (cmp > 0 && tc.want <= 0) {
			t.Errorf("compare %s to minimum: got %d, want sign %d", tc.version, cmp, tc.want)
		}
	}
}

func TestReapLegacySingBoxProcesses(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "sing-box")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "inbound-1.json")
	if err := os.WriteFile(configPath, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	helper := filepath.Join(dir, "legacy-sing-box")
	if err := os.WriteFile(helper, []byte("#!/bin/sh\ntrap 'exit 0' TERM INT\nwhile :; do sleep 1; done\n"), 0700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(helper, "run", "-c", configPath)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		select {
		case <-done:
		case <-time.After(time.Second):
		}
	})
	pidPath := filepath.Join(dir, "inbound-1.pid")
	if err := os.WriteFile(pidPath, []byte(strconv.Itoa(cmd.Process.Pid)), 0600); err != nil {
		t.Fatal(err)
	}
	if got := reapLegacySingBoxProcesses(filepath.Dir(dir)); got != 1 {
		t.Fatalf("清理数量 = %d, want 1 (pid=%d cmd=%s)", got, cmd.Process.Pid, fmt.Sprint(cmd.Args))
	}
	deadline := time.Now().Add(time.Second)
	for processAlive(cmd.Process.Pid) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if processAlive(cmd.Process.Pid) {
		t.Fatal("旧版子进程仍在运行")
	}
	if _, err := os.Stat(pidPath); !os.IsNotExist(err) {
		t.Fatalf("旧 PID 文件未删除: %v", err)
	}
}

func processAlive(pid int) bool {
	_, err := os.Stat(fmt.Sprintf("/proc/%d", pid))
	return err == nil
}

func TestSingBoxCandidatesCustomName(t *testing.T) {
	candidates := singBoxCandidates("/var/lib/fanout", "sing-box-custom")
	if len(candidates) != 1 || candidates[0] != "/var/lib/fanout/bin/sing-box-custom" {
		t.Fatalf("自定义 sing-box 文件名候选路径错误: %#v", candidates)
	}
	if _, err := findSingBox("/var/lib/fanout", "/opt/proxy/sing-box"); err == nil {
		t.Fatal("带路径的自定义二进制参数应被拒绝")
	}
}

func TestSingBoxProcWritePIDReturnsError(t *testing.T) {
	dir := t.TempDir()
	proc := &singBoxProc{dir: filepath.Join(dir, "missing"), name: "inbound-1"}
	if err := proc.writePID(123); err == nil {
		t.Fatal("PID 目录不存在时应返回写入错误")
	}
	if _, err := os.Stat(filepath.Join(dir, "missing", "inbound-1.pid")); !os.IsNotExist(err) {
		t.Fatalf("写入失败时不应留下 PID 文件: %v", err)
	}
}
