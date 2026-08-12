package main

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"time"
)

const (
	maxNativeInboundProcesses = 64
	nativeWatchInterval       = 5 * time.Second
	nativeWatchBackoffMax     = time.Minute
	nativeStartWorkers        = 8
)

// Native is fanout's sing-box-backed inbound manager.
//
// 入站数据存在 native.json。每个启用的入站都由独立 sing-box 进程托管，
// 因而改动一个入站不会中断其他入站上的客户端连接。
type Native struct {
	mu             sync.Mutex
	dir            string
	listenAddr     string
	inboundPortMin int
	inboundPortMax int
	store          *nativeStore
	// proc is the shared child-process template retained for compatibility with
	// existing state/tests. Each enabled inbound gets its own derived process.
	proc        *singBoxProc
	procs       map[int]*singBoxProc
	configHash  map[int][sha256.Size]byte
	lastTunnels []*Tunnel
	hasTunnels  bool
	watchStop   chan struct{}
	watchDone   chan struct{}
	closed      bool
	watchFails  map[int]nativeWatchFailure
	watchErrors map[int]string
}

type nativeWatchFailure struct {
	count int
	next  time.Time
	hash  [sha256.Size]byte
}

type inboundReconcileError struct {
	failures map[int]error
}

func (e *inboundReconcileError) Error() string {
	parts := make([]string, 0, len(e.failures))
	for id, err := range e.failures {
		parts = append(parts, fmt.Sprintf("入站 %d: %v", id, err))
	}
	return strings.Join(parts, "; ")
}

type inboundStartWork struct {
	id   int
	proc *singBoxProc
	hash [sha256.Size]byte
	cfg  map[string]any
}

func openNative(workDir string, listen ...string) (*Native, error) {
	listenAddr := "0.0.0.0"
	if len(listen) > 0 && strings.TrimSpace(listen[0]) != "" {
		listenAddr = strings.TrimSpace(listen[0])
	}
	return openNativeConfigured(workDir, listenAddr, inboundPortMinDefault, inboundPortMaxDefault)
}

func openNativeConfigured(workDir, listenAddr string, portMin, portMax int, binary ...string) (*Native, error) {
	if workDir == "" {
		return nil, fmt.Errorf("自建模式缺少工作目录")
	}
	if strings.TrimSpace(listenAddr) == "" {
		listenAddr = "0.0.0.0"
	}
	if err := validateInboundListenAddr(listenAddr); err != nil {
		return nil, err
	}
	if err := validatePortRange(portMin, portMax); err != nil {
		return nil, err
	}
	bin, err := findSingBox(workDir, binary...)
	if err != nil {
		return nil, err
	}
	if err := validateSingBox(bin); err != nil {
		return nil, err
	}
	store, err := loadNativeStore(workDir)
	if err != nil {
		return nil, err
	}
	// XHTTP is Xray-specific. Keep legacy records visible for deletion, but do
	// not let an old enabled entry prevent the sing-box gateway from starting.
	for _, inbound := range store.Inbounds {
		if inbound.Network == "xhttp" {
			inbound.Enable = false
			if !strings.Contains(inbound.Remark, "XHTTP 不兼容") {
				inbound.Remark += " [XHTTP 不兼容]"
			}
		}
	}
	if count := store.enabledInboundCount(); count > maxNativeInboundProcesses {
		return nil, fmt.Errorf("已启用 %d 个自建入站，超过 %d 个 sing-box 子进程上限；请先在 native.json 中禁用或删除多余入站", count, maxNativeInboundProcesses)
	}
	n := &Native{
		dir:            workDir,
		listenAddr:     listenAddr,
		inboundPortMin: portMin,
		inboundPortMax: portMax,
		store:          store,
		proc:           &singBoxProc{bin: bin, dir: filepath.Join(workDir, "sing-box"), name: "gateway"},
		procs:          make(map[int]*singBoxProc),
		configHash:     make(map[int][sha256.Size]byte),
		watchFails:     make(map[int]nativeWatchFailure),
		watchErrors:    make(map[int]string),
		watchStop:      make(chan struct{}),
		watchDone:      make(chan struct{}),
	}
	// Stop the legacy aggregate gateway left behind by pre-v3.0.2 versions.
	n.proc.reapOrphan()
	for _, inbound := range store.Inbounds {
		n.inboundProc(inbound.ID).reapOrphan()
	}
	go n.watchInbounds()
	return n, nil
}

func (n *Native) Kind() string { return "native" }

func (n *Native) Describe() string { return "fanout 自建 sing-box (>=1.14)" }

// apply regenerates each inbound's isolated sing-box configuration. Changes to
// one inbound therefore restart only that inbound instead of all clients.
// 调用方必须已持有 n.mu。
func (n *Native) apply(tunnels []*Tunnel) error {
	return n.reconcile(tunnels, true, nil)
}

// reconcile applies the current store to child processes. Persist is false
// for the watchdog because restarting an exited child does not alter state.
// 调用方必须已持有 n.mu。
func (n *Native) reconcile(tunnels []*Tunnel, persist bool, forceIDs map[int]bool) error {
	n.lastTunnels = append(n.lastTunnels[:0], tunnels...)
	n.hasTunnels = true
	if n.procs == nil {
		n.procs = make(map[int]*singBoxProc)
	}
	if n.configHash == nil {
		n.configHash = make(map[int][sha256.Size]byte)
	}
	if n.watchFails == nil {
		n.watchFails = make(map[int]nativeWatchFailure)
	}
	if n.watchErrors == nil {
		n.watchErrors = make(map[int]string)
	}
	// Upgrade hostname-based bindings from earlier releases. Route IDs stay
	// stable across VPN Gate node swaps and avoid rewriting gateway routes.
	legacy := make(map[string]string, len(tunnels))
	for _, t := range tunnels {
		state := t.snapshot()
		legacy[sanitizeTag(state.Node.HostName)] = tunnelBinding(t)
	}
	for _, ib := range n.store.Inbounds {
		if replacement, ok := legacy[ib.BoundTo]; ok {
			ib.BoundTo = replacement
		}
	}

	list := n.store.sorted()
	desired := make(map[int]bool, len(list))
	works := make([]inboundStartWork, 0, len(list))
	failures := make(map[int]error)
	for _, inbound := range list {
		desired[inbound.ID] = inbound.Enable
		proc := n.inboundProc(inbound.ID)
		if !inbound.Enable {
			proc.stop()
			delete(n.configHash, inbound.ID)
			delete(n.procs, inbound.ID)
			delete(n.watchFails, inbound.ID)
			delete(n.watchErrors, inbound.ID)
			continue
		}
		work, err := n.prepareInboundWork(inbound, tunnels, time.Now(), forceIDs[inbound.ID])
		if err != nil {
			failures[inbound.ID] = err
			continue
		}
		if work != nil {
			works = append(works, *work)
		}
	}
	for _, result := range runInboundStarts(works) {
		if result.err != nil {
			n.recordWatchFailure(result.work.id, result.work.hash, time.Now(), result.err)
			failures[result.work.id] = result.err
			continue
		}
		n.configHash[result.work.id] = result.work.hash
		delete(n.watchErrors, result.work.id)
	}
	for id, proc := range n.procs {
		if desired[id] {
			continue
		}
		proc.stop()
		delete(n.configHash, id)
		delete(n.procs, id)
		delete(n.watchFails, id)
		delete(n.watchErrors, id)
	}
	if len(failures) > 0 {
		return &inboundReconcileError{failures: failures}
	}
	if !persist {
		return nil
	}
	return n.store.save(n.dir)
}

// reconcileInbound renders and starts one enabled inbound worker. Keeping this
// shared with the watchdog prevents recovery from drifting from normal apply.
// 调用方必须已持有 n.mu。
func (n *Native) prepareInboundWork(inbound *nativeInbound, tunnels []*Tunnel, now time.Time, force bool) (*inboundStartWork, error) {
	copyInbound := *inbound
	copyInbound.Listen = n.listenAddr
	proc := n.inboundProc(inbound.ID)
	cfg := buildSingBoxGatewayConfig([]*nativeInbound{&copyInbound}, tunnels)
	configBlob, err := json.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(configBlob)
	if failure, ok := n.watchFails[inbound.ID]; ok && failure.hash == hash && !force && !nativeRetryDue(failure, now) {
		return nil, nil
	}
	if previous, ok := n.configHash[inbound.ID]; ok && previous == hash && !proc.exited() {
		return nil, nil
	}
	return &inboundStartWork{id: inbound.ID, proc: proc, hash: hash, cfg: cfg}, nil
}

func startInboundWork(work inboundStartWork) error {
	path, err := writeSingBoxConfig(work.proc.dir, work.proc.name, work.cfg)
	if err != nil {
		return err
	}
	if err := verifySingBoxConfig(work.proc.bin, path); err != nil {
		return err
	}
	if err := work.proc.start(path); err != nil {
		return err
	}
	if work.proc.exited() {
		return fmt.Errorf("sing-box 启动后立即退出")
	}
	return nil
}

type inboundStartResult struct {
	work inboundStartWork
	err  error
}

func runInboundStarts(works []inboundStartWork) []inboundStartResult {
	if len(works) == 0 {
		return nil
	}
	workers := nativeStartWorkers
	if workers > len(works) {
		workers = len(works)
	}
	jobs := make(chan inboundStartWork)
	results := make(chan inboundStartResult, len(works))
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for work := range jobs {
				results <- inboundStartResult{work: work, err: startInboundWork(work)}
			}
		}()
	}
	go func() {
		for _, work := range works {
			jobs <- work
		}
		close(jobs)
		wg.Wait()
		close(results)
	}()
	out := make([]inboundStartResult, 0, len(works))
	for result := range results {
		out = append(out, result)
	}
	return out
}

func (n *Native) reconcileInbound(inbound *nativeInbound, tunnels []*Tunnel, now time.Time, force bool) error {
	work, err := n.prepareInboundWork(inbound, tunnels, now, force)
	if err != nil || work == nil {
		return err
	}
	if err := startInboundWork(*work); err != nil {
		n.recordWatchFailure(work.id, work.hash, now, err)
		return err
	}
	n.configHash[work.id] = work.hash
	delete(n.watchErrors, work.id)
	return nil
}

func (n *Native) recordWatchFailure(id int, hash [sha256.Size]byte, now time.Time, err error) {
	failure := n.watchFails[id]
	if failure.hash != hash {
		failure = nativeWatchFailure{hash: hash}
	}
	failure.count++
	failure.next = now.Add(nativeRetryDelay(failure.count))
	n.watchFails[id] = failure
	if n.watchErrors == nil {
		n.watchErrors = make(map[int]string)
	}
	if err != nil {
		n.watchErrors[id] = strings.TrimSpace(err.Error())
	}
}

func (n *Native) watchInbounds() {
	ticker := time.NewTicker(nativeWatchInterval)
	defer ticker.Stop()
	defer close(n.watchDone)
	for {
		select {
		case <-n.watchStop:
			return
		case now := <-ticker.C:
			n.mu.Lock()
			if n.closed {
				n.mu.Unlock()
				return
			}
			if n.hasTunnels {
				n.watchExitedInbounds(now)
			}
			n.mu.Unlock()
		}
	}
}

// watchExitedInbounds restarts only workers that exited. Failed starts use a
// per-inbound exponential backoff so a broken certificate or configuration
// cannot execute sing-box check every five seconds forever.
// 调用方必须已持有 n.mu。
func (n *Native) watchExitedInbounds(now time.Time) {
	for _, inbound := range n.store.Inbounds {
		if !inbound.Enable {
			continue
		}
		proc := n.inboundProc(inbound.ID)
		if !proc.exited() {
			// A worker that survives until the next sweep is considered stable.
			delete(n.watchFails, inbound.ID)
			continue
		}
		failure := n.watchFails[inbound.ID]
		if !nativeRetryDue(failure, now) {
			continue
		}
		if err := n.reconcileInbound(inbound, n.lastTunnels, now, false); err != nil {
			log.Printf("自建入站 %d 守护重启失败（%s 后重试）: %v", inbound.ID, nativeRetryDelay(n.watchFails[inbound.ID].count), err)
			continue
		}
	}
}

func nativeRetryDelay(failures int) time.Duration {
	if failures < 1 {
		return 0
	}
	delay := nativeWatchInterval
	for i := 1; i < failures && delay < nativeWatchBackoffMax; i++ {
		delay *= 2
	}
	if delay > nativeWatchBackoffMax {
		return nativeWatchBackoffMax
	}
	return delay
}

func nativeRetryDue(failure nativeWatchFailure, now time.Time) bool {
	return failure.next.IsZero() || !now.Before(failure.next)
}

func (n *Native) inboundProc(id int) *singBoxProc {
	if n.procs == nil {
		n.procs = make(map[int]*singBoxProc)
	}
	if proc := n.procs[id]; proc != nil {
		return proc
	}
	proc := &singBoxProc{
		bin: n.proc.bin, dir: n.proc.dir,
		name: fmt.Sprintf("inbound-%d", id),
	}
	n.procs[id] = proc
	return proc
}

// commitMutation applies a changed store. If sing-box rejects or cannot start
// the new configuration, restore both the in-memory store and the last known
// good runtime configuration.
// The caller must hold n.mu.
func (n *Native) commitMutation(before *nativeStore, tunnels []*Tunnel) error {
	changed := changedInboundIDs(before, n.store)
	if err := n.reconcile(tunnels, true, changed); err == nil {
		return nil
	} else {
		applyErr := err
		var runtimeErr *inboundReconcileError
		if errors.As(err, &runtimeErr) && !runtimeErr.affects(changed) {
			// An unrelated worker is already broken. Persist the requested
			// change and leave that worker under its own backoff instead of
			// blocking all healthy inbound administration.
			if saveErr := n.store.save(n.dir); saveErr != nil {
				return fmt.Errorf("应用配置失败: %w；保存已应用的其他入站失败: %v", applyErr, saveErr)
			}
			log.Printf("部分自建入站未应用，但其他修改已保存: %v", applyErr)
			return nil
		}
		n.store = before
		if rollbackErr := n.reconcile(tunnels, true, changed); rollbackErr != nil {
			return fmt.Errorf("应用新配置失败: %w；恢复旧配置也失败: %v", applyErr, rollbackErr)
		}
		return applyErr
	}
}

func (e *inboundReconcileError) affects(ids map[int]bool) bool {
	for id := range e.failures {
		if ids[id] {
			return true
		}
	}
	return false
}

func changedInboundIDs(before, after *nativeStore) map[int]bool {
	changed := make(map[int]bool)
	oldByID := make(map[int]*nativeInbound, len(before.Inbounds))
	newByID := make(map[int]*nativeInbound, len(after.Inbounds))
	for _, inbound := range before.Inbounds {
		oldByID[inbound.ID] = inbound
	}
	for _, inbound := range after.Inbounds {
		newByID[inbound.ID] = inbound
	}
	for id, inbound := range oldByID {
		if next, ok := newByID[id]; !ok || !reflect.DeepEqual(inbound, next) {
			changed[id] = true
		}
	}
	for id, inbound := range newByID {
		if old, ok := oldByID[id]; !ok || !reflect.DeepEqual(old, inbound) {
			changed[id] = true
		}
	}
	return changed
}

// OnTunnelsChanged 在隧道集合变化后重建配置。自建模式下出站直接由隧道列表
// 推导，所以隧道一变就要重新生成，否则新出口没有对应的 socks 出站。
func (n *Native) OnTunnelsChanged(tunnels []*Tunnel) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.apply(tunnels)
}

func (n *Native) SetInboundPortRange(min, max int) error {
	if err := validatePortRange(min, max); err != nil {
		return err
	}
	n.mu.Lock()
	n.inboundPortMin, n.inboundPortMax = min, max
	n.mu.Unlock()
	return nil
}

// Close 停掉自己拉起的 sing-box。
func (n *Native) Close() {
	n.mu.Lock()
	if n.closed {
		n.mu.Unlock()
		return
	}
	n.closed = true
	if n.watchStop != nil {
		close(n.watchStop)
	}
	for _, proc := range n.procs {
		proc.stop()
	}
	// Also clean up a legacy aggregate gateway if one was adopted during an
	// interrupted upgrade.
	if n.proc != nil {
		n.proc.stop()
	}
	watchDone := n.watchDone
	n.mu.Unlock()
	if watchDone != nil {
		<-watchDone
	}
}

func (n *Native) Inbounds(live map[string]bool) ([]Inbound, error) {
	n.mu.Lock()
	defer n.mu.Unlock()

	list := n.store.sorted()
	out := make([]Inbound, 0, len(list))
	for _, ib := range list {
		status, runtimeErr, retryAt := n.inboundRuntime(ib)
		out = append(out, Inbound{
			ID: ib.ID, Port: ib.Port, Protocol: ib.Protocol,
			Remark: ib.Remark, Enable: ib.Enable, Tag: ib.tag(),
			BoundTo: ib.BoundTo, BoundUp: live[ib.BoundTo],
			RuntimeStatus: status, RuntimeError: runtimeErr, RetryAt: retryAt,
		})
	}
	return out, nil
}

func (n *Native) InboundDetail(id int, publicHost string) (*InboundDetail, error) {
	n.mu.Lock()
	defer n.mu.Unlock()

	ib := n.store.byID(id)
	if ib == nil {
		return nil, fmt.Errorf("入站 %d 不存在", id)
	}
	detail := &InboundDetail{
		Inbound: Inbound{
			ID: ib.ID, Port: ib.Port, Protocol: ib.Protocol,
			Remark: ib.Remark, Enable: ib.Enable, Tag: ib.tag(),
			BoundTo: ib.BoundTo,
		},
		Listen:  n.listenAddr,
		Network: ib.netOrTCP(),
		TLS:     "none",
	}
	detail.RuntimeStatus, detail.RuntimeError, detail.RetryAt = n.inboundRuntime(ib)
	for _, c := range ib.Clients {
		id := c.ID
		if ib.Protocol == "trojan" || ib.Protocol == "hysteria2" {
			id = c.Password
		}
		detail.Clients = append(detail.Clients, ClientInfo{Email: c.Email, ID: id, Enable: c.Enable})
		detail.Links = append(detail.Links, shareLink(ib, c, publicHost))
	}
	return detail, nil
}

// inboundRuntime reports the child-process state, rather than only the
// persisted Enable switch. The caller must hold n.mu.
func (n *Native) inboundRuntime(inbound *nativeInbound) (string, string, time.Time) {
	if !inbound.Enable {
		return "disabled", "", time.Time{}
	}

	proc := n.procs[inbound.ID]
	if proc != nil && !proc.exited() {
		return "running", "", time.Time{}
	}

	runtimeErr := n.watchErrors[inbound.ID]
	if proc != nil {
		if err, exited := proc.lastExit(); exited && runtimeErr == "" {
			if err != nil {
				runtimeErr = fmt.Sprintf("sing-box 子进程已退出: %v", err)
			} else {
				runtimeErr = "sing-box 子进程已退出"
			}
		}
	}
	if failure, ok := n.watchFails[inbound.ID]; ok {
		if runtimeErr == "" {
			runtimeErr = "sing-box 子进程未运行，等待守护重启"
		}
		return "retrying", runtimeErr, failure.next
	}
	if runtimeErr != "" {
		return "retrying", runtimeErr, time.Time{}
	}
	return "stopped", runtimeErr, time.Time{}
}

func (n *Native) InboundLinks(ids []int, publicHost string) ([]string, error) {
	n.mu.Lock()
	defer n.mu.Unlock()

	var out []string
	for _, id := range ids {
		ib := n.store.byID(id)
		if ib == nil {
			continue
		}
		for _, c := range ib.Clients {
			out = append(out, shareLink(ib, c, publicHost))
		}
	}
	return out, nil
}

func (n *Native) Bind(inboundTag string, hostname string, tunnels []*Tunnel) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	var target *Tunnel
	if hostname != "" {
		for _, t := range tunnels {
			if t.snapshot().Node.HostName == hostname {
				target = t
				break
			}
		}
		if target == nil {
			return fmt.Errorf("节点 %s 没有运行中的隧道", hostname)
		}
		targetState := target.snapshot()
		if targetState.Status != "up" {
			return fmt.Errorf("节点 %s 的隧道还没连通（当前 %s）", hostname, targetState.Status)
		}
	}

	var found *nativeInbound
	for _, ib := range n.store.Inbounds {
		if ib.tag() == inboundTag {
			found = ib
			break
		}
	}
	if found == nil {
		return fmt.Errorf("入站 %s 不存在", inboundTag)
	}

	before := n.store.clone()
	if target == nil {
		found.BoundTo = ""
	} else {
		found.BoundTo = tunnelBinding(target)
	}
	return n.commitMutation(before, tunnels)
}

func (n *Native) Rebind(oldHost string, target *Tunnel, tunnels []*Tunnel) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	oldTag := sanitizeTag(oldHost)
	newTag := tunnelBinding(target)
	newLabel := exitLabel(target)
	before := n.store.clone()
	for _, ib := range n.store.Inbounds {
		if ib.BoundTo != oldTag && ib.BoundTo != newTag {
			continue
		}
		ib.BoundTo = newTag
		// 备注里带着旧出口的地区和 IP 尾段，换了节点要跟着改
		ib.Remark = renameExitSuffix(ib.Remark, newLabel)
	}
	return n.commitMutation(before, tunnels)
}

func (n *Native) ResyncOutbound(t *Tunnel, tunnels []*Tunnel) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.apply(tunnels)
}

// CloneToTunnels 以某个入站为模板，为每条指定隧道复制一个入站并绑好出口。
//
// 客户端凭据整套沿用模板：同一个 UUID 能走所有出口，用户只改端口。
func (n *Native) CloneToTunnels(templateID int, hosts []string, tunnels []*Tunnel) ([]int, error) {
	n.mu.Lock()
	defer n.mu.Unlock()

	tpl := n.store.byID(templateID)
	if tpl == nil {
		return nil, fmt.Errorf("模板入站 %d 不存在", templateID)
	}

	byHost := map[string]*Tunnel{}
	for _, t := range tunnels {
		byHost[t.snapshot().Node.HostName] = t
	}
	targets := make([]*Tunnel, 0, len(hosts))
	seenHosts := make(map[string]bool, len(hosts))
	for _, host := range hosts {
		if seenHosts[host] {
			continue
		}
		seenHosts[host] = true
		t := byHost[host]
		if t != nil && t.snapshot().Status == "up" {
			targets = append(targets, t)
		}
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("没有可用的隧道")
	}
	if n.store.enabledInboundCount()+len(targets) > maxNativeInboundProcesses {
		return nil, fmt.Errorf("复制后将运行 %d 个自建入站，超过 %d 个 sing-box 子进程上限", n.store.enabledInboundCount()+len(targets), maxNativeInboundProcesses)
	}

	listenerNet := tpl.listenNetwork()
	used := n.store.usedPorts(listenerNet)
	if listenerNet == "tcp" {
		for port := range tunnelTCPPorts(tunnels) {
			used[port] = true
		}
	}
	created := []int{}
	before := n.store.clone()
	for _, t := range targets {
		port, err := freeRandomInboundPort(used, n.inboundPortMin, n.inboundPortMax, listenerNet)
		if err != nil {
			n.store = before
			return nil, err
		}
		used[port] = true

		clone := &nativeInbound{
			ID:       n.store.NextID,
			Port:     port,
			Protocol: tpl.Protocol,
			Network:  tpl.Network,
			Path:     tpl.Path,
			Host:     tpl.Host,
			// 安全层必须跟着复制：漏掉的话从 REALITY/TLS 模板复制出来的
			// 入站会变成明文，而分享链接照样标着模板的协议，很难发现
			Security: tpl.Security,
			TLS:      tpl.TLS,
			Reality:  tpl.Reality,
			Remark:   cloneRemark(tpl.Remark, exitLabel(t)),
			Enable:   true,
			Clients:  append([]nativeClient(nil), tpl.Clients...),
			BoundTo:  tunnelBinding(t),
		}
		n.store.NextID++
		n.store.Inbounds = append(n.store.Inbounds, clone)
		created = append(created, port)
	}

	if err := n.commitMutation(before, tunnels); err != nil {
		return nil, err
	}
	return created, nil
}

func (n *Native) DeleteInbounds(ids []int, tunnels []*Tunnel) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	before := n.store.clone()
	drop := map[int]bool{}
	for _, id := range ids {
		drop[id] = true
	}
	kept := make([]*nativeInbound, 0, len(n.store.Inbounds))
	for _, ib := range n.store.Inbounds {
		if !drop[ib.ID] {
			kept = append(kept, ib)
		}
	}
	n.store.Inbounds = kept
	return n.commitMutation(before, tunnels)
}

// UpdateInbound 改端口、备注与启停。
//
// 端口变了 inboundTag 也跟着变（tag 里含端口），所以路由规则要一起重写；
// apply 是整份重建，天然覆盖了这点。
func (n *Native) UpdateInbound(id int, patch InboundPatch, tunnels []*Tunnel) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	ib := n.store.byID(id)
	if ib == nil {
		return fmt.Errorf("入站 %d 不存在", id)
	}

	before := n.store.clone()
	portChanged := patch.Port != nil && *patch.Port != ib.Port
	if portChanged {
		port := *patch.Port
		if port < 1 || port > 65535 {
			return fmt.Errorf("端口 %d 不在合法范围", port)
		}
		for _, other := range n.store.Inbounds {
			if other.ID != id && other.Port == port && other.listenNetwork() == ib.listenNetwork() {
				return fmt.Errorf("端口 %d 已被入站 %q 占用", port, other.Remark)
			}
		}
		if ib.listenNetwork() == "tcp" && tunnelUsesTCPPort(tunnels, port) {
			return fmt.Errorf("端口 %d 已预留给公网 SOCKS5 出口", port)
		}
		if !portAvailable(port, ib.listenNetwork()) {
			return fmt.Errorf("端口 %d 的 %s/%s 监听已被占用", port, ib.listenNetwork(), "IPv4+IPv6")
		}
		ib.Port = port
	}
	if patch.Remark != nil {
		if r := strings.TrimSpace(*patch.Remark); r != "" {
			ib.Remark = r
		}
	}
	if patch.Enable != nil {
		if *patch.Enable && !ib.Enable && n.store.enabledInboundCount() >= maxNativeInboundProcesses {
			return fmt.Errorf("已达到 %d 个自建入站的 sing-box 子进程上限", maxNativeInboundProcesses)
		}
		if *patch.Enable && !ib.Enable && !hasEnabledClient(ib) {
			return fmt.Errorf("入站没有启用的客户端，无法启用")
		}
		if *patch.Enable && ib.listenNetwork() == "tcp" && tunnelUsesTCPPort(tunnels, ib.Port) {
			return fmt.Errorf("端口 %d 已预留给公网 SOCKS5 出口", ib.Port)
		}
		if *patch.Enable && !ib.Enable && !portChanged && !portAvailable(ib.Port, ib.listenNetwork()) {
			return fmt.Errorf("端口 %d 的 %s/%s 监听已被占用", ib.Port, ib.listenNetwork(), "IPv4+IPv6")
		}
		ib.Enable = *patch.Enable
	}
	return n.commitMutation(before, tunnels)
}

func hasEnabledClient(inbound *nativeInbound) bool {
	for _, client := range inbound.Clients {
		if client.Enable {
			return true
		}
	}
	return false
}

// AddClient 给入站加一个客户端。同一入站上可以有多套凭据，便于分发给不同人。
func (n *Native) AddClient(id int, email string, tunnels []*Tunnel) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	ib := n.store.byID(id)
	if ib == nil {
		return fmt.Errorf("入站 %d 不存在", id)
	}

	email = strings.TrimSpace(email)
	if email == "" {
		email = fmt.Sprintf("%s-%d-%s", ib.Protocol, ib.Port, randomHex(3))
	}
	for _, c := range ib.Clients {
		if c.Email == email {
			return fmt.Errorf("客户端 %q 已存在", email)
		}
	}

	before := n.store.clone()
	ib.Clients = append(ib.Clients, nativeClient{
		Email:    email,
		ID:       newUUID(),
		Password: randomHex(8),
		Enable:   true,
		Flow:     visionFlow(ib),
	})
	return n.commitMutation(before, tunnels)
}

// DeleteClient 摘掉一个客户端。留下最后一个是有意的：
// 没有任何客户端的入站虽然合法，但谁也连不上，只会让人以为坏了。
func (n *Native) DeleteClient(id int, email string, tunnels []*Tunnel) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	ib := n.store.byID(id)
	if ib == nil {
		return fmt.Errorf("入站 %d 不存在", id)
	}
	if len(ib.Clients) <= 1 {
		return fmt.Errorf("这是最后一个客户端，删掉就没人能连了")
	}

	kept := make([]nativeClient, 0, len(ib.Clients))
	for _, c := range ib.Clients {
		if c.Email != email {
			kept = append(kept, c)
		}
	}
	if len(kept) == len(ib.Clients) {
		return fmt.Errorf("客户端 %q 不存在", email)
	}
	before := n.store.clone()
	ib.Clients = kept
	return n.commitMutation(before, tunnels)
}

// ResetClient 换一套新凭据，旧链接立即失效。
func (n *Native) ResetClient(id int, email string, tunnels []*Tunnel) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	ib := n.store.byID(id)
	if ib == nil {
		return fmt.Errorf("入站 %d 不存在", id)
	}
	for i := range ib.Clients {
		if ib.Clients[i].Email == email {
			before := n.store.clone()
			ib.Clients[i].ID = newUUID()
			ib.Clients[i].Password = randomHex(8)
			return n.commitMutation(before, tunnels)
		}
	}
	return fmt.Errorf("客户端 %q 不存在", email)
}

// visionFlow 沿用入站已有客户端的 flow，让新加的客户端与其余保持一致。
func visionFlow(ib *nativeInbound) string {
	for _, c := range ib.Clients {
		if c.Flow != "" {
			return c.Flow
		}
	}
	return ""
}

// NewInboundSpec 是自建模式下新建入站的参数。
//
// 留空的字段都有合理默认：端口随机、备注按协议加端口自动生成、
// 路径随机、REALITY 的密钥与 shortId 自动生成。
type NewInboundSpec struct {
	Protocol string
	Network  string
	Port     int
	Remark   string
	Path     string
	Host     string
	Security string
	// Vision 请求给 VLESS 客户端启用 xtls-rprx-vision
	Vision bool

	// TLS：留空 CertFile 就生成自签证书
	ServerName string
	CertFile   string
	KeyFile    string

	// REALITY
	Dest        string
	ServerNames string // 逗号分隔，留空则从 Dest 推出来
	ShortID     string
	Fingerprint string
}

// nativeProtocols 是自建模式支持的协议，与前端下拉保持一致。
var nativeProtocols = map[string]bool{"vless": true, "vmess": true, "trojan": true, "hysteria2": true, "tuic": true}

// CreateInbound 新建一个入站，端口留空时随机分配。
func (n *Native) CreateInbound(spec NewInboundSpec, tunnels []*Tunnel) (*CreatedInbound, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.store.enabledInboundCount() >= maxNativeInboundProcesses {
		return nil, fmt.Errorf("已达到 %d 个自建入站的 sing-box 子进程上限", maxNativeInboundProcesses)
	}
	before := n.store.clone()

	requestedNetwork := strings.ToLower(strings.TrimSpace(spec.Network))
	if requestedNetwork == "" {
		proto := strings.ToLower(strings.TrimSpace(spec.Protocol))
		if proto == "hysteria2" || proto == "tuic" {
			requestedNetwork = "udp"
		} else {
			requestedNetwork = "tcp"
		}
	}
	listenerNet := listenerNetwork(requestedNetwork)
	used := n.store.usedPorts(listenerNet)
	if listenerNet == "tcp" {
		for port := range tunnelTCPPorts(tunnels) {
			used[port] = true
		}
	}
	ns, err := normalizeInboundSpec(spec, used, n.inboundPortMin, n.inboundPortMax)
	if err != nil {
		return nil, err
	}
	proto, network, security, port := ns.Protocol, ns.Network, ns.Security, ns.Port

	ib := &nativeInbound{
		ID:       n.store.NextID,
		Port:     port,
		Protocol: proto,
		Network:  network,
		Path:     ns.Path,
		Host:     ns.Host,
		Security: security,
		Remark:   ns.Remark,
		Enable:   true,
	}

	switch security {
	case "tls":
		conf, err := buildTLS(n.dir, spec)
		if err != nil {
			return nil, err
		}
		ib.TLS = conf
	case "reality":
		conf, err := buildReality(n.proc.bin, spec)
		if err != nil {
			return nil, err
		}
		ib.Reality = conf
	}

	ib.Clients = []nativeClient{{
		Email:    fmt.Sprintf("%s-%d", proto, port),
		ID:       newUUID(),
		Password: randomHex(8),
		Flow:     ns.Flow,
		Enable:   true,
	}}

	n.store.NextID++
	n.store.Inbounds = append(n.store.Inbounds, ib)

	if err := n.commitMutation(before, tunnels); err != nil {
		return nil, err
	}
	return &CreatedInbound{
		ID:       ib.ID,
		Port:     ib.Port,
		Protocol: ib.Protocol,
		Remark:   ib.Remark,
		Network:  ib.netOrTCP(),
		Security: ib.securityOrNone(),
	}, nil
}

// cloneRemark gives copied inbounds a stable, readable name.
func cloneRemark(base, label string) string {
	base = strings.TrimSpace(base)
	if base == "" {
		return label
	}
	return base + "-" + label
}

// shareLink 生成客户端可直接导入的分享链接。
func shareLink(ib *nativeInbound, c nativeClient, host string) string {
	net := ib.netOrTCP()
	sec := ib.securityOrNone()

	q := url.Values{}
	if ib.Protocol != "hysteria2" {
		q.Set("type", net)
		q.Set("security", sec)
	}

	switch net {
	case "ws", "httpupgrade":
		q.Set("path", ib.Path)
		if ib.Host != "" {
			q.Set("host", ib.Host)
		}
	case "grpc":
		q.Set("serviceName", strings.TrimPrefix(ib.Path, "/"))
	}

	switch sec {
	case "tls":
		if ib.TLS != nil {
			if ib.TLS.ServerName != "" {
				q.Set("sni", ib.TLS.ServerName)
			}
			// 自签证书需要靠指纹让客户端固定信任这一张。
			if ib.TLS.SelfSigned && ib.TLS.CertSha256 != "" {
				q.Set("pinSHA256", ib.TLS.CertSha256)
			}
			if ib.Protocol == "hysteria2" && ib.TLS.SelfSigned {
				q.Set("insecure", "1")
			}
		}
	case "reality":
		if ib.Reality != nil {
			if len(ib.Reality.ServerNames) > 0 {
				q.Set("sni", ib.Reality.ServerNames[0])
			}
			// pbk 是分享链接的通用写法，各家客户端都认。
			q.Set("pbk", ib.Reality.PublicKey)
			if len(ib.Reality.ShortIDs) > 0 {
				q.Set("sid", ib.Reality.ShortIDs[0])
			}
			if ib.Reality.Fingerprint != "" {
				q.Set("fp", ib.Reality.Fingerprint)
			}
		}
	}

	if c.Flow != "" && ib.Protocol == "vless" {
		q.Set("flow", c.Flow)
	}

	frag := url.PathEscape(ib.Remark)

	switch ib.Protocol {
	case "hysteria2":
		return fmt.Sprintf("hysteria2://%s@%s:%d/?%s#%s", url.PathEscape(c.Password), host, ib.Port, q.Encode(), frag)
	case "tuic":
		q.Set("congestion_control", "cubic")
		return fmt.Sprintf("tuic://%s:%s@%s:%d/?%s#%s", c.ID, url.PathEscape(c.Password), host, ib.Port, q.Encode(), frag)
	case "trojan":
		return fmt.Sprintf("trojan://%s@%s:%d?%s#%s", c.Password, host, ib.Port, q.Encode(), frag)
	case "vmess":
		// vmess 的 base64 形式各家客户端解析不一，用通用的 URI 形式
		q.Set("encryption", "auto")
		return fmt.Sprintf("vmess://%s@%s:%d?%s#%s", c.ID, host, ib.Port, q.Encode(), frag)
	default:
		q.Set("encryption", "none")
		return fmt.Sprintf("vless://%s@%s:%d?%s#%s", c.ID, host, ib.Port, q.Encode(), frag)
	}
}

// buildTLS 组装 TLS 配置。没给证书路径就生成一张自签的，落在 dir/certs 下。
func buildTLS(dir string, spec NewInboundSpec) (*tlsConfig, error) {
	name := strings.TrimSpace(spec.ServerName)
	if name == "" {
		name = "localhost"
	}
	conf := &tlsConfig{ServerName: name}

	cert, key := strings.TrimSpace(spec.CertFile), strings.TrimSpace(spec.KeyFile)
	// 只填一个多半是漏填，静默退回自签会让用户以为用上了自己的证书
	if (cert == "") != (key == "") {
		return nil, fmt.Errorf("证书和私钥要成对填写，或者都留空用自签证书")
	}
	if cert != "" && key != "" {
		if _, err := os.Stat(cert); err != nil {
			return nil, fmt.Errorf("证书文件不可读: %w", err)
		}
		if _, err := os.Stat(key); err != nil {
			return nil, fmt.Errorf("私钥文件不可读: %w", err)
		}
		conf.CertFile, conf.KeyFile = cert, key
		return conf, nil
	}

	// 自签证书验不过 CA，靠链接里的证书指纹让客户端固定信任
	c, k, err := selfSignedCert(dir, name)
	if err != nil {
		return nil, err
	}
	conf.CertFile, conf.KeyFile, conf.SelfSigned = c, k, true
	// 指纹是自签证书唯一能让客户端验过的凭据，算不出来就没法生成可用链接
	fp, err := certFingerprint(c)
	if err != nil {
		return nil, err
	}
	conf.CertSha256 = fp
	return conf, nil
}

// buildReality 组装 REALITY 配置，密钥和 shortId 都自动生成。
// singBoxBin is used to generate a REALITY key pair.
func buildReality(singBoxBin string, spec NewInboundSpec) (*realityConfig, error) {
	dest := strings.TrimSpace(spec.Dest)
	if dest == "" {
		// REALITY 要跟 dest 完成一次真实 TLS1.3 握手，dest 不稳会让所有连接
		// 静默回落。microsoft.com 在部分机房握手经常走不完，这里选更可靠的。
		dest = "www.tesla.com:443"
	}
	if !strings.Contains(dest, ":") {
		dest += ":443"
	}

	var names []string
	for _, s := range strings.Split(spec.ServerNames, ",") {
		if s = strings.TrimSpace(s); s != "" {
			names = append(names, s)
		}
	}
	if len(names) == 0 {
		// 默认用 dest 的主机名：REALITY 要求 SNI 与被借用的站点一致
		names = []string{strings.SplitN(dest, ":", 2)[0]}
	}

	priv, pub, err := realityKeys(singBoxBin)
	if err != nil {
		return nil, err
	}
	if err := checkRealityDest(dest, names[0]); err != nil {
		return nil, fmt.Errorf("REALITY 目标站点不可用，换一个 dest: %w", err)
	}

	short := strings.TrimSpace(spec.ShortID)
	if short == "" {
		short = randomShortID()
	}
	fp := strings.TrimSpace(spec.Fingerprint)
	if fp == "" {
		fp = "chrome"
	}

	return &realityConfig{
		Dest:        dest,
		ServerNames: names,
		PrivateKey:  priv,
		PublicKey:   pub,
		ShortIDs:    []string{short},
		Fingerprint: fp,
	}, nil
}
