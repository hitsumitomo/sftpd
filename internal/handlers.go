package internal

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/sys/unix"
)

// fileInfo implements fs.FileInfo for virtual directory entries
type fileInfo struct {
	name    string
	size    int64
	mode    fs.FileMode
	modTime time.Time
	isDir   bool
	sys     any
}

func (v *fileInfo) Name() string       { return v.name    }
func (v *fileInfo) Size() int64        { return v.size    }
func (v *fileInfo) Mode() fs.FileMode  { return v.mode    }
func (v *fileInfo) ModTime() time.Time { return v.modTime }
func (v *fileInfo) IsDir() bool        { return v.isDir   }
func (v *fileInfo) Sys() any           { return v.sys     }

// Static virtual file info for parent directory
var (
	parentDir = []fs.FileInfo{
		&fileInfo{
			name:    "..",
			size:    1024,
			mode:    fs.ModeDir | DefaultDirectoryMode,
			isDir:   true,
			modTime: time.Now(),
		},
	}
)

// virtualFSHandler implements sftp handlers with virtual filesystem
type virtualFSHandler struct {
	sync.Mutex
	user *User
	uid  uint32
	gid  uint32
}

// resolveMapping parses a virtual path and returns the mapping and relative path inside the mapping
func (v *virtualFSHandler) resolveMapping(virtualPath string) (*Mapping, string, error) {
	if strings.Contains(virtualPath, "~") {
		return nil, "", os.ErrPermission
	}

	cleanPath := filepath.Clean(virtualPath)
	parts := strings.SplitN(strings.TrimPrefix(cleanPath, "/"), "/", 2)
	if len(parts[0]) == 0 {
		return nil, "", nil // root
	}

	v.Lock()
	m, ok := v.user.mapping[parts[0]]
	v.Unlock()

	if !ok {
		return nil, "", os.ErrNotExist
	}

	if m.Mode == ExecMode {
		return m, "", nil
	}

	rel := "."
	if len(parts) > 1 && parts[1] != "" {
		rel = parts[1]
	}

	return m, rel, nil
}

// Fileread handles file read requests for SFTP
func (v *virtualFSHandler) Fileread(req *sftp.Request) (io.ReaderAt, error) {
	m, rel, err := v.resolveMapping(req.Filepath)
	if err != nil || m == nil {
		return nil, os.ErrNotExist
	}

	if m.Mode == ExecMode {
		log.Print(`Fileread: user "%s" read output "%s"`, v.user.login, m.Path)
		v.Lock()
		defer v.Unlock()

		if m.output == nil {
			return nil, os.ErrNotExist
		}
		return bytes.NewReader(m.output), nil
	}

	f, err := m.root.Open(rel)
	if err != nil {
		return nil, err
	}
	return f, nil
}

// Filewrite handles file write requests for SFTP
func (v *virtualFSHandler) Filewrite(req *sftp.Request) (io.WriterAt, error) {
	m, rel, err := v.resolveMapping(req.Filepath)
	if err != nil || m == nil {
		return nil, os.ErrNotExist
	}

	if m.Mode == ExecMode {
		if m.Path != "" {
			log.Print(`Filewrite: user "%s" executed "%s"`, v.user.login, m.Path)
			parts := strings.Fields(m.Path)

			if len(parts) == 0 {
				return nil, os.ErrNotExist
			}

			ctx, cancel := context.WithTimeout(context.Background(), ExecTimeout)
			defer cancel()

			cmd := exec.CommandContext(ctx, parts[0], parts[1:]...)
			m.output, _ = cmd.CombinedOutput()

			return discardReaderWriterAt{}, nil
		}
		return nil, os.ErrNotExist
	}

	if m.Mode == ReadOnly {
		return nil, os.ErrPermission
	}

	dir := filepath.Dir(rel)
	if err := m.root.Mkdir(dir, DefaultDirectoryMode); err != nil && !os.IsExist(err) {
		return nil, err
	}

	f, err := m.root.OpenFile(rel, os.O_RDWR|os.O_CREATE|os.O_TRUNC, DefaultFileMode)
	if err != nil {
		return nil, err
	}
	return f, nil
}

// Filecmd handles file command requests (remove, mkdir, rmdir, rename, etc.)
func (v *virtualFSHandler) Filecmd(req *sftp.Request) error {
	m, rel, err := v.resolveMapping(req.Filepath)
	if err != nil || m == nil {
		return os.ErrNotExist
	}

	if m.Mode != ReadWrite && (req.Method == "Remove" || req.Method == "Mkdir" || req.Method == "Rmdir" || req.Method == "Rename") {
		return os.ErrPermission
	}

	switch req.Method {
	case "Remove", "Rmdir":
		if err := m.root.Remove(rel); err != nil {
			return err
		}
		return nil

	case "Mkdir":
		err = m.root.Mkdir(rel, DefaultDirectoryMode)
		if err != nil && !os.IsExist(err) {
			return err
		}
		return nil

	case "Rename":
		targetM, targetRel, targetErr := v.resolveMapping(req.Target)
		if targetErr != nil || targetM == nil {
			return os.ErrNotExist
		}
		if m.root == targetM.root {
			if err := os.Rename(
				filepath.Join(m.root.Name(), rel),
				filepath.Join(targetM.root.Name(), targetRel),
			); err != nil {
				return err
			}
			return nil
		}
		return fmt.Errorf("rename across roots not supported")
	}
	// case "Setstat", "Chmod", "Chown", "Utimens", "Symlink":
	return nil
}

// Filelist handles directory listing requests for SFTP
func (v *virtualFSHandler) Filelist(req *sftp.Request) (sftp.ListerAt, error) {
	cleanPath := filepath.Clean(req.Filepath)

	if cleanPath == "/" {
		var infos []fs.FileInfo
		for name, m := range v.user.mapping {
			mode := fs.ModeDir
			switch m.Mode {
			case ReadOnly:
				mode |= ReadOnlyDirectoryMode

			case ReadWrite:
				mode |= DefaultDirectoryMode

			case ExecMode:
				continue
			}
			infos = append(infos, &fileInfo{
				name:    name,
				size:    1024,
				mode:    mode,
				isDir:   true,
				modTime: time.Now(),
			})
		}
		return listerAtFunc(func() ([]fs.FileInfo, error) {
			return infos, nil
		}), nil
	}

	m, relPath, err := v.resolveMapping(req.Filepath)
	if err != nil || m == nil {
		return nil, os.ErrNotExist
	}

	// read output of exec mode
	if m.Mode == ExecMode {
		info := &fileInfo{
			name:    filepath.Base(req.Filepath),
			size:    int64(len(m.output)),
			mode:    DefaultFileMode,
			modTime: time.Now(),
			isDir:   false,
		}
		return listerAtFunc(func() ([]fs.FileInfo, error) {
			return []fs.FileInfo{info}, nil
		}), nil
	}

	info, err := m.root.Stat(relPath)
	if err != nil {
		return nil, err
	}

	if !info.IsDir() {
		return listerAtFunc(func() ([]fs.FileInfo, error) {
			return []fs.FileInfo{info}, nil
		}), nil
	}

	f, err := m.root.Open(relPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	entries, err := f.Readdir(0)
	if err != nil {
		return nil, err
	}

	// Filter out non-regular files and directories and out of permission
	filtered := entries[:0]
	for _, entry := range entries {
		if !(entry.Mode().IsRegular() || entry.Mode().IsDir()) {
			continue
		}

		if stat, ok := entry.Sys().(*syscall.Stat_t); ok && stat != nil {
			if v.checkReadableStat(stat.Uid, stat.Gid, stat.Mode) {
				filtered = append(filtered, entry)
			}
			continue
		}

		// Try unix.Stat if syscall.Stat_t is not available
		fullPath := filepath.Join(m.root.Name(), relPath, entry.Name())
		var unixStat unix.Stat_t
		if err := unix.Stat(fullPath, &unixStat); err == nil {
			if v.checkReadableStat(unixStat.Uid, unixStat.Gid, unixStat.Mode) {
				filtered = append(filtered, entry)
			}
		}
	}

	infos := append(parentDir, filtered...)
	return listerAtFunc(func() ([]fs.FileInfo, error) {
		return infos, nil
	}), nil
}

// checkReadableStat returns true if the file is readable by v.uid/v.gid using stat struct and mode
func (v *virtualFSHandler) checkReadableStat(owner, group uint32, mode uint32) bool {
	switch {
	case v.uid == 0:
		return true
	case v.uid == owner && mode & 0400 != 0: // owner can read
		return true
	case v.gid == group && mode & 0040 != 0: // group can read
		return true
	case mode & 0004 != 0:                   // others can read
		return true
	}
	return false
}


