//go:build windows

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
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

func startInJob(job windows.Handle, root, image string, args ...string) (*exec.Cmd, error) {
	path := filepath.Join(root, image)
	command := exec.Command(path, args...)
	command.Dir = root
	command.Stdout = nil
	command.Stderr = nil
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
		return nil, err
	}
	defer windows.CloseHandle(handle)
	if err := windows.AssignProcessToJobObject(job, handle); err != nil {
		_ = command.Process.Kill()
		return nil, err
	}
	return command, nil
}

func runChildren(root string, stop <-chan struct{}, ready chan<- struct{}) error {
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
	defer windows.CloseHandle(job)

	dpi, err := startInJob(job, root, "goodbyedpi.exe", "-5", "--blacklist", filepath.Join(root, "discord-hosts.txt"))
	if err != nil {
		return fmt.Errorf("start GoodbyeDPI: %w", err)
	}
	gateway, err := startInJob(job, root, "go-pcap2socks.exe", filepath.Join(root, "gateway-windows.json"))
	if err != nil {
		return fmt.Errorf("start userspace gateway: %w", err)
	}
	exited := make(chan error, 2)
	go func() { exited <- dpi.Wait() }()
	go func() { exited <- gateway.Wait() }()
	startup := time.NewTimer(500 * time.Millisecond)
	select {
	case <-stop:
		startup.Stop()
		return nil
	case err := <-exited:
		startup.Stop()
		if err == nil {
			return errors.New("a required runtime process stopped during startup")
		}
		return fmt.Errorf("a required runtime process failed during startup: %w", err)
	case <-startup.C:
	}
	ready <- struct{}{}
	select {
	case <-stop:
		return nil
	case err := <-exited:
		if err == nil {
			return errors.New("a required runtime process stopped")
		}
		return fmt.Errorf("a required runtime process failed: %w", err)
	}
}

func (service) Execute(_ []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	const accepted = svc.AcceptStop | svc.AcceptShutdown
	status <- svc.Status{State: svc.StartPending}
	root, err := executableRoot()
	if err != nil {
		return false, 1
	}
	stop := make(chan struct{})
	ready := make(chan struct{}, 1)
	done := make(chan error, 1)
	go func() { done <- runChildren(root, stop, ready) }()
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
					return false, 1
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
