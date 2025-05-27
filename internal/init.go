package internal

import (
	"fmt"
	"net"
	"time"

	"sftp/pkg/cipher"
	"sftp/pkg/logger"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
)

const VERSION = "sftpd v1.0"

var log *logger.Logger

// New initializes logging, loads config and returns SFTPD instance.
func New(configFile, logFile string) (sftpd *SFTPD, err error) {
	log = logger.New(logFile)
	// log.Printf("log file: %s", logFile)

	sftpd = &SFTPD{
		userPubKeyMap: make(map[string]*User), // fingerprint -> *User
		configFile:    configFile,
		secure:	       cipher.New(),
	}

	if err := sftpd.LoadConfig(); err != nil {
		return nil, err
	}
	return sftpd, nil
}

// Start launches the SSH/SFTPD server and begins accepting connections.
func (s *SFTPD) Start() {
	s.setupSSHConfig()

	if err := s.setupHostKey(); err != nil {
		log.Fatal("Failed to setup host key: %v", err)
	}

	if err := s.startListener(); err != nil {
		log.Fatal("Failed to start listener: %v", err)
	}

	if err := s.dropPrivileges(); err != nil {
		log.Fatal("Failed to drop privileges: %v", err)
	}

	s.startSSHConnectionHandler()
	s.startHTTPServer()
}

// setupSSHConfig configures SSH server settings
func (s *SFTPD) setupSSHConfig() {
	s.sshConfig = &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if user := s.getUserByPassword(c.User(), string(pass)); user != nil {
				return &ssh.Permissions{
					Extensions: map[string]string{
						"login":         user.login,
						"authenticated": "password",
					},
				}, nil
			}
			return nil, ErrPermissionDenied
		},
		PublicKeyCallback: func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if user := s.getUserByPublicKey(&key); user != nil {
				return &ssh.Permissions{
					Extensions: map[string]string{
						"login":         user.login,
						"authenticated": "public key",
					},
				}, nil
			}
			return nil, ErrUnknownPublicKey
		},
		MaxAuthTries:  3,
		ServerVersion: SSHVersion,
	}
}

// setupHostKey adds the host private key to SSH config
func (s *SFTPD) setupHostKey() error {
	priv, err := ssh.ParsePrivateKey([]byte(s.config.private))
	if err != nil {
		return fmt.Errorf("bad private key: %v", err)
	}
	s.sshConfig.AddHostKey(priv)
	return nil
}

// startListener creates and starts the TCP listener
func (s *SFTPD) startListener() error {
	var err error
	s.listener, err = net.Listen("tcp", s.config.Addr)
	if err != nil {
		return err
	}

	log.Print(`listen on "%s"`, s.config.Addr)
	return nil
}

// dropPrivileges drops root privileges to configured UID/GID
func (s *SFTPD) dropPrivileges() error {
	if err := unix.Setgid(int(s.config.GID)); err != nil {
		return fmt.Errorf("setgid failed: %v", err)
	}

	if err := unix.Setuid(int(s.config.UID)); err != nil {
		return fmt.Errorf("setuid failed: %v", err)
	}

	return nil
}

// startSSHConnectionHandler starts the goroutine that accepts connections
func (s *SFTPD) startSSHConnectionHandler() {
	go func() {
		for {
			conn, err := s.listener.Accept()
			if err != nil {
				if opErr, ok := err.(*net.OpError); ok && opErr.Timeout() {
					log.Error("Accept timeout: %v", err)
					time.Sleep(time.Second)
					continue
				}

				log.Fatal("Fatal accept error: %v", err)
				return
			}
			go s.handleConn(conn)
		}
	}()
}

// startHTTPServer starts the HTTP server if configured
func (s *SFTPD) startHTTPServer() {
	if s.config.HTTP.Addr != "" {
		go func() {
			if err := s.serveHTTP(); err != nil {
				log.Error("http server error: %v", err)
			}
		}()
	}
}

