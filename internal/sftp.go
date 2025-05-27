package internal

import (
	"fmt"
	"net"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// handleConn handles a new SSH connection and SFTP subsystem requests
func (s *SFTPD) handleConn(conn net.Conn) {
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	sshConn, chans, reqs, err := ssh.NewServerConn(conn, s.sshConfig)
	if err != nil {
		log.Error("SSH handshake failed: %v %v", err, conn.RemoteAddr())
		return
	}
	conn.SetDeadline(time.Time{})

	var login, authenticated string
	if sshConn.Permissions != nil {
		if l, ok := sshConn.Permissions.Extensions["login"]; ok && l != "" {
			login = l
		}
		if a, ok := sshConn.Permissions.Extensions["authenticated"]; ok && a != "" {
			authenticated = a
		}

	} else {
		log.Error("SSH permissions not found")
		sshConn.Close()
		return
	}

	var ip net.IP
	if addr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		ip = addr.IP

	} else {
		log.Error("Failed to get remote IP address")
		sshConn.Close()
		return
	}

	user := s.getUserByLogin(login)
	if user == nil {
		log.Error(`User "%s" not found in config`, login)
		sshConn.Close()
		return
	}

	if !user.Allowed(ip) {
		log.Error(`User "%s" not allowed from IP %s`, login, ip)
		sshConn.Close()
		return
	}

	if err = s.AddSession(login, authenticated, ip, sshConn); err != nil {
		log.Error(`User "%s": %v`, login, err)
		sshConn.Close()
		return
	}
	defer s.DeleteSession(login, sshConn)

	go ssh.DiscardRequests(reqs)

	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "unsupported channel type")
			continue
		}

		channel, requests, err := newChannel.Accept()
		if err != nil {
			log.Error("Channel accept failed: %v", err)
			continue
		}

		go func(in <-chan *ssh.Request) {
			defer channel.Close()

			for req := range in {
				if req.Type == "subsystem" && len(req.Payload) >= 5 && string(req.Payload[4:]) == "sftp" {
					req.Reply(true, nil)

					vfs := &virtualFSHandler{
						user: user,
						uid:  s.config.UID,
						gid:  s.config.GID,
					}

					handlers := sftp.Handlers{
						FileGet:  vfs,
						FilePut:  vfs,
						FileCmd:  vfs,
						FileList: vfs,
					}

					server := sftp.NewRequestServer(channel, handlers)
					defer server.Close()

					_ = server.Serve()
					return
				}
				req.Reply(false, nil)
			}
		}(requests)
	}
}

// updateActivity updates the last activity timestamp for a session, if needed
func (s *SFTPD) updateActivity(login string, conn *ssh.ServerConn) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if sessions, ok := s.sessions[login]; ok {
		if info, exists := sessions[conn]; exists {
			info.LastActivity = time.Now()
		}
	}
}

// DropLogin closes all sessions for a user
func (s *SFTPD) DropLogin(login string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	sessions, ok := s.sessions[login]
	if ok {
		for conn := range sessions {
			go conn.Close()
		}
		delete(s.sessions, login)
	}
}

// AddSession adds a new session for a user
func (s *SFTPD) AddSession(login, authenticated string, ip net.IP, conn *ssh.ServerConn) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.sessions == nil {
		s.sessions = make(map[string]map[*ssh.ServerConn]*SessionInfo)
	}

	if s.sessions[login] == nil {
		s.sessions[login] = make(map[*ssh.ServerConn]*SessionInfo)
	}

	if maxSessions := s.config.Users[login].MaxSessions; maxSessions > 0 {
		if len(s.sessions[login]) >= maxSessions {
			return fmt.Errorf("maximum number of sessions (%d) reached", maxSessions)
		}
	}

	s.sessions[login][conn] = &SessionInfo{
		LastActivity: time.Now(),
		ip:           ip.String(),
	}

	log.Print(`user "%s" connected from %s (authenticated by %s, %s)`, login, ip, authenticated, conn.ClientVersion())
	return nil
}

// DeleteSession closes a specific session for a user
func (s *SFTPD) DeleteSession(login string, conn *ssh.ServerConn) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if sessions, ok := s.sessions[login]; ok {
		if session, exists := sessions[conn]; exists {
			go conn.Close()
			delete(sessions, conn)

			if len(sessions) == 0 {
				delete(s.sessions, login)
			}
			log.Print(`user "%s" disconnected from %s`, login, session.ip)
		}
	}
}
