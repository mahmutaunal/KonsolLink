//go:build windows

package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
)

const serviceName = "KonsolLink"

type service struct{}

func executableRoot() (string, error) {
	path, err := os.Executable()
	if err != nil {
		return "", err
	}
	path, err = filepath.EvalSymlinks(path)
	if err != nil {
		return "", err
	}
	return filepath.Dir(path), nil
}

func newKillOnCloseJob() (windows.Handle, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return 0, err
	}
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	_, err = windows.SetInformationJobObject(
		job,
		windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)),
		uint32(unsafe.Sizeof(info)),
	)
	if err != nil {
		windows.CloseHandle(job)
		return 0, err
	}
	return job, nil
}

func startInJob(job windows.Handle, root, image string, env []string, output *tailWriter, args ...string) (*exec.Cmd, error) {
	path := filepath.Join(root, image)
	command := exec.Command(path, args...)
	command.Dir = root
	command.Env = append(os.Environ(), env...)
	command.Stdout = output
	command.Stderr = output
	command.WaitDelay = time.Second
	if err := command.Start(); err != nil {
		return nil, err
	}
	handle, err := windows.OpenProcess(
		windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE|windows.PROCESS_QUERY_LIMITED_INFORMATION,
		false,
		uint32(command.Process.Pid),
	)
	if err != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		return nil, err
	}
	defer windows.CloseHandle(handle)
	if err := windows.AssignProcessToJobObject(job, handle); err != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		return nil, err
	}
	return command, nil
}

func runChildren(root string, stop <-chan struct{}, ready chan<- struct{}, diagnostic *diagnostics) error {
	if err := validateManifest(root); err != nil {
		return err
	}
	// gopacket loads Npcap from the protected System32\Npcap directory. Check
	// that exact location before starting either child; never search the current
	// directory for a capture DLL.
	systemRoot := filepath.Clean(os.Getenv("SystemRoot"))
	if filepath.VolumeName(systemRoot) == "" || filepath.Dir(systemRoot) == systemRoot {
		return errors.New("Windows SystemRoot is unavailable")
	}
	pcapPath := filepath.Join(systemRoot, "System32", "Npcap", "wpcap.dll")
	if info, statErr := os.Stat(pcapPath); statErr != nil || !info.Mode().IsRegular() {
		return fmt.Errorf("Npcap is required at the protected system path: %s", pcapPath)
	}
	job, err := newKillOnCloseJob()
	if err != nil {
		return err
	}
	var children sync.WaitGroup
	defer func() { _ = windows.CloseHandle(job); children.Wait() }()

	// Allocate an ephemeral loopback port and a per-run authentication secret.
	// A competing listener cannot forge the token or the expected gateway PID.
	reservation, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return err
	}
	address := reservation.Addr().String()
	_ = reservation.Close()
	secret := make([]byte, 32)
	if _, err = rand.Read(secret); err != nil {
		return err
	}
	token := hex.EncodeToString(secret)
	dpiOutput, gatewayOutput := &tailWriter{}, &tailWriter{}
	exited := make(chan error, 2)
	dpi, err := startInJob(job, root, "goodbyedpi.exe", nil, dpiOutput, "-5", "--blacklist", filepath.Join(root, "discord-hosts.txt"))
	if err != nil {
		return fmt.Errorf("start GoodbyeDPI: %w", err)
	}
	children.Add(1)
	go func() {
		defer children.Done()
		exited <- errors.New(errorSummary("goodbyedpi.exe", dpi.Wait(), dpiOutput))
	}()
	gateway, err := startInJob(job, root, "go-pcap2socks.exe", []string{"KONSOLLINK_HEALTH_ADDR=" + address, "KONSOLLINK_HEALTH_TOKEN=" + token}, gatewayOutput, filepath.Join(root, "gateway-windows.json"))
	if err != nil {
		return fmt.Errorf("start gateway: %w", err)
	}
	children.Add(1)
	go func() {
		defer children.Done()
		exited <- errors.New(errorSummary("go-pcap2socks.exe", gateway.Wait(), gatewayOutput))
	}()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client := &http.Client{Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	type result struct {
		health healthResult
		err    error
	}
	results := make(chan result, 1)
	// One worker only. Starting/stopping, process supervision and SCM requests
	// continue while DNS/TLS probes run; the GUI never participates.
	probe := func() {
		go func() {
			h, e := probeHealth(ctx, client, address, token, gateway.Process.Pid)
			select {
			case results <- result{h, e}:
			case <-ctx.Done():
			}
		}()
	}
	startup := time.NewTimer(500 * time.Millisecond)
	defer startup.Stop()
	select {
	case <-stop:
		return nil
	case err := <-exited:
		return err
	case <-startup.C:
	}
	if err = diagnostic.write("checking", "Windows ağ kontrolü: ilk doğrulama bekleniyor."); err != nil {
		return err
	}
	ready <- struct{}{}
	timer := time.NewTimer(healthInterval)
	defer timer.Stop()
	policy := healthPolicy{}
	probe()
	for {
		select {
		case <-stop:
			return nil
		case err := <-exited:
			return err
		case <-timer.C:
			probe()
		case r := <-results:
			message, restart := policy.observe(r.health, r.err)
			state := "healthy"
			if message != "" {
				state = "degraded"
			}
			if restart {
				return errors.New(message)
			}
			if err = diagnostic.write(state, message); err != nil {
				return fmt.Errorf("write diagnostics: %w", err)
			}
			timer.Reset(healthInterval)
		}
	}

}

func (service) Execute(_ []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	const accepted = svc.AcceptStop | svc.AcceptShutdown
	status <- svc.Status{State: svc.StartPending}
	root, err := executableRoot()
	if err != nil {
		return false, 1
	}
	diagnostic := newDiagnostics(root)
	if err = diagnostic.write("starting", ""); err != nil {
		reportFailure(err)
		return false, 1
	}
	stop := make(chan struct{})
	ready := make(chan struct{}, 1)
	done := make(chan error, 1)
	go func() {
		err := runChildren(root, stop, ready, diagnostic)
		if err != nil {
			_ = diagnostic.write("failed", err.Error())
			reportFailure(err)
		} else {
			_ = diagnostic.write("stopped", "")
		}
		done <- err
	}()
	select {
	case <-ready:
	case <-time.After(10 * time.Second):
		close(stop)
		return false, 1
	case <-done:
		return false, 1
	}
	status <- svc.Status{State: svc.Running, Accepts: accepted}
	for {
		select {
		case request := <-requests:
			switch request.Cmd {
			case svc.Interrogate:
				status <- request.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				close(stop)
				select {
				case err = <-done:
				case <-time.After(5 * time.Second):
					err = errors.New("runtime shutdown timed out")
				}
				if err != nil {
					reportFailure(err)
				}
				return false, 0
			}
		case err = <-done:
			if err != nil {
				return false, 1
			}
			return false, 0
		}
	}
}

func main() {
	if err := svc.Run(serviceName, service{}); err != nil {
		os.Exit(1)
	}
}

func reportFailure(err error) {
	log, e := eventlog.Open(serviceName)
	if e == nil {
		defer log.Close()
		_ = log.Error(1, err.Error())
	}
}
