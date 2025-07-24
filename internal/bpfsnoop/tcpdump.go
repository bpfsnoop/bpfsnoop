package bpfsnoop

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

const (
	tcpdumpCmd = "tcpdump"
)

var tcpdumpArgs = []string{
	"-r", "-", // Read from stdin
	"-nnnev",                 // Disable name resolution and enable verbosity
	"--immediate-mode", "-l", // Enable immediate mode for line-buffered output
}

type tcpdumpRunner struct {
	stdin  io.WriteCloser
	stdout io.ReadCloser
	stderr io.ReadCloser
	cmd    *exec.Cmd

	buf   []byte
	pcapw *pcapgo.Writer
}

func newTcpdumpRunner() (*tcpdumpRunner, error) {
	cmdPath, err := exec.LookPath(tcpdumpCmd)
	if err != nil {
		return nil, fmt.Errorf("tcpdump command not found: %w", err)
	}

	cmd := exec.Command(cmdPath, tcpdumpArgs...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdin pipe: %w", err)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stderr pipe: %w", err)
	}

	go func() {
		fd, _ := os.Open("/dev/null")
		defer fd.Close()
		io.Copy(fd, stderr) // Redirect stderr to /dev/null
	}()

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start tcpdump command: %w", err)
	}

	pcapw := pcapgo.NewWriter(stdin)
	pcapw.WriteFileHeader(65535, layers.LinkTypeEthernet)

	return &tcpdumpRunner{
		stdin:  stdin,
		stdout: stdout,
		stderr: stderr,
		pcapw:  pcapw,
		cmd:    cmd,

		buf: make([]byte, 4096*4),
	}, nil
}

func (r *tcpdumpRunner) kill() error {
	if r.cmd.Process != nil {
		if err := r.cmd.Process.Kill(); err != nil {
			return fmt.Errorf("failed to kill tcpdump process: %w", err)
		}

		if err := r.cmd.Wait(); err != nil {
			return fmt.Errorf("failed to wait for tcpdump process to exit: %w", err)
		}
	}

	return nil
}

func (r *tcpdumpRunner) close() error {
	if r == nil {
		return nil
	}

	if err := r.stdin.Close(); err != nil {
		return fmt.Errorf("failed to close stdin pipe: %w", err)
	}

	if err := r.stdout.Close(); err != nil {
		return fmt.Errorf("failed to close stdout pipe: %w", err)
	}

	if err := r.stderr.Close(); err != nil {
		return fmt.Errorf("failed to close stderr pipe: %w", err)
	}

	return r.kill()
}

func (r *tcpdumpRunner) sendBuffer(buf []byte) error {
	info := gopacket.CaptureInfo{
		Timestamp:      time.Now(),
		CaptureLength:  len(buf),
		Length:         len(buf),
		InterfaceIndex: 0,
	}
	err := r.pcapw.WritePacket(info, buf)
	if err != nil {
		return fmt.Errorf("failed to send pkt to tcpdump stdin: %w", err)
	}

	return nil
}

func (r *tcpdumpRunner) decode(buf []byte) (string, error) {
	err := r.sendBuffer(buf)
	if err != nil {
		return "", fmt.Errorf("failed to send buffer to tcpdump: %w", err)
	}

	n, err := r.stdout.Read(r.buf)
	if err != nil {
		return "", fmt.Errorf("failed to read from tcpdump stdout: %w", err)
	}
	return string(r.buf[:n]), nil
}
