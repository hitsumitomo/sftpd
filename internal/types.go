package internal

import (
	"errors"
	"io"
	"io/fs"
	"net"
	"os"
	"sftp/pkg/cipher"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	ReadOnly  = "ro"
	ReadWrite = "rw"
	ExecMode  = "exec"

	ExecTimeout = 10 * time.Second

    DefaultFileMode       = 0644
    DefaultDirectoryMode  = 0755
	ReadOnlyDirectoryMode = 0555

	// Maximum number of open files per session
	MaxOpenFilesPerSession = 100

	SSHVersion = "SSH-2.0-OpenSSH_9.2p2 Debian-2+deb12u6" // any fake version
)

var (
	ErrPermissionDenied = errors.New("permission denied")
	ErrUnknownPublicKey = errors.New("unknown public key")
	ErrSessionTimeout   = errors.New("session timeout")
	ErrTooManyFiles     = errors.New("too many open files")
)

//   █████████  ███████████ ███████████ ███████████  ██████████
//  ███░░░░░███░░███░░░░░░█░█░░░███░░░█░░███░░░░░███░░███░░░░███
// ░███    ░░░  ░███   █ ░ ░   ░███  ░  ░███    ░███ ░███   ░░███
// ░░█████████  ░███████       ░███     ░██████████  ░███    ░███
//  ░░░░░░░░███ ░███░░░█       ░███     ░███░░░░░░   ░███    ░███
//  ███    ░███ ░███  ░        ░███     ░███         ░███    ███
// ░░█████████  █████          █████    █████        ██████████
//  ░░░░░░░░░  ░░░░░          ░░░░░    ░░░░░        ░░░░░░░░░░

// SFTPD is the main structure for the SFTP server
type SFTPD struct {
	config        *Config
	configFile    string
	secure        *cipher.Cipher

	mutex         sync.Mutex
	userPubKeyMap map[string]*User
	sessions      map[string]map[*ssh.ServerConn]*SessionInfo

	sshConfig     *ssh.ServerConfig
	listener      net.Listener
}

// SessionInfo holds information about an active session
type SessionInfo struct {
	LastActivity time.Time
	ip           string
}

// ---------------------------------------------------------------------------- discardReaderWriterAt
// implements io.WriterAt and io.ReaderAt
type discardReaderWriterAt struct{}

func (discardReaderWriterAt) WriteAt(p []byte, off int64) (int, error) {
	return len(p), nil
}

func (discardReaderWriterAt) ReadAt(p []byte, off int64) (int, error) {
	return 0, io.EOF
}
// ---------------------------------------------------------------------------- /discardReaderWriterAt

// ---------------------------------------------------------------------------- listerAtFunc
type listerAtFunc func() ([]fs.FileInfo, error)

// ListAt implements the sftp.ListerAt interface for directory listings
func (f listerAtFunc) ListAt(p []fs.FileInfo, off int64) (int, error) {
	all, err := f()
	if err != nil {
		return 0, err
	}

	if int(off) >= len(all) {
		return 0, io.EOF
	}

	n := copy(p, all[off:])
	if int(off)+n >= len(all) {
		return n, io.EOF
	}
	return n, nil
}
// ---------------------------------------------------------------------------- /listerAtFunc

//    █████████                         ██████   ███
//   ███░░░░░███                       ███░░███ ░░░
//  ███     ░░░   ██████  ████████    ░███ ░░░  ████   ███████
// ░███          ███░░███░░███░░███  ███████   ░░███  ███░░███
// ░███         ░███ ░███ ░███ ░███ ░░░███░     ░███ ░███ ░███
// ░░███     ███░███ ░███ ░███ ░███   ░███      ░███ ░███ ░███
//  ░░█████████ ░░██████  ████ █████  █████     █████░░███████
//   ░░░░░░░░░   ░░░░░░  ░░░░ ░░░░░  ░░░░░     ░░░░░  ░░░░░███
//                                                    ███ ░███
//                                                   ░░██████
//                                                    ░░░░░░

type Config struct{
	Addr            string             `json:"addr"`
	HTTP            httpConfig	       `json:"http,omitempty,omitzero"`
	UID             uint32             `json:"uid"`
	GID             uint32             `json:"gid"`
	Private         string             `json:"private"` // Encrypted
	private         string                              // Plain
	Groups          map[string]*Group  `json:"groups"`
	Users           map[string]*User   `json:"users"`
}

type httpConfig struct {
    Addr     string   `json:"addr"`
    URL      string   `json:"url"`
    url      string   // decrypted runtime URL
    Username string   `json:"username"`
    username string   // decrypted runtime Username
    Password string   `json:"password"`
    password string   // decrypted runtime Password
    token    string
    Filter   FilterIP `json:"filter,omitempty,omitzero"`
}

// Mapping describes a virtual folder mapping for a user or group
type Mapping struct {
	Path   string   `json:"path,omitempty"`
	Mode   string   `json:"mode"`
	root   *os.Root
	output []byte
}

// FilterIP describes IP filtering for a user or group
type FilterIP struct {
	Whitelist string `json:"whitelist,omitempty,omitzero"` // CSV string
	whitelist []net.IPNet
	Blacklist string `json:"blacklist,omitempty,omitzero"` // CSV string
	blacklist []net.IPNet
}

// Group describes a group in the config
type Group struct {
	Mapping map[string]*Mapping `json:"mapping"`
	Filter  FilterIP            `json:"filter,omitempty,omitzero"`
}

// User describes a user in the config
type User struct {
	Password string              `json:"password,omitempty"`     // Encrypted
	PubKey   string              `json:"pubkey,omitempty"`       // Encrypted
	MaxSessions int              `json:"max_sessions,omitempty"` // 0 = unlimited
	Groups   string              `json:"groups,omitempty"`       // CSV string
	Filter   FilterIP            `json:"filter,omitempty,omitzero"`
	Mapping  map[string]*Mapping `json:"mapping,omitempty,omitzero"` // own mapping

	// runtime
	login    string
	password string
	pubkey   string
	mapping  map[string]*Mapping // own + group mappings
}

// Allowed checks if the given IP is allowed for this user (whitelist/blacklist logic).
func (u *User) Allowed(ip net.IP) bool {
	for _, n := range u.Filter.blacklist {
		if n.Contains(ip) {
			return false
		}
	}

	if len(u.Filter.whitelist) == 0 {
		return true
	}

	for _, n := range u.Filter.whitelist {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

