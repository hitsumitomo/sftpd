package internal

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"
)

// LoadConfig loads and processes the SFTPD configuration file.
func (s *SFTPD) LoadConfig(reader ...io.Reader) (err error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	var (
		newConfig *Config
		dec       *json.Decoder
	)

	if len(reader) > 0 && reader[0] != nil {
		dec = json.NewDecoder(reader[0])
	} else {
		f, err := os.Open(s.configFile)
		if err != nil {
			log.Error("Failed to open config file: %v", err)
			return err
		}
		defer f.Close()
		dec = json.NewDecoder(f)
	}

	if err = dec.Decode(&newConfig); err != nil {
		log.Error("Failed to decode config: %v", err)
		return err
	}

	// Define old values for HTTP fields
	var oldUsername, oldPassword, oldURL string
	if s.config != nil {
		oldUsername = s.config.HTTP.username
		oldPassword = s.config.HTTP.password
		oldURL      = s.config.HTTP.url
	}

	// Process HTTP fields using the helper
	s.processSecureField(&newConfig.HTTP.Username, &newConfig.HTTP.username, oldUsername)
	s.processSecureField(&newConfig.HTTP.Password, &newConfig.HTTP.password, oldPassword)
	s.processSecureField(&newConfig.HTTP.URL,      &newConfig.HTTP.url,      oldURL)

	// Process Private field with the same helper
	s.processSecureField(&newConfig.Private, &newConfig.private, "")

	// Parse HTTP filter
	newConfig.HTTP.Filter.whitelist = parseIPNetList(newConfig.HTTP.Filter.Whitelist)
	newConfig.HTTP.Filter.blacklist = parseIPNetList(newConfig.HTTP.Filter.Blacklist)

	// Parse group filters
	for _, group := range newConfig.Groups {
		group.Filter.whitelist = parseIPNetList(group.Filter.Whitelist)
		group.Filter.blacklist = parseIPNetList(group.Filter.Blacklist)
	}

	// Reset public key map
	s.userPubKeyMap = make(map[string]*User)

	// log.Dump(newConfig)

	// Set up all group mapping roots before processing users
	for _, group := range newConfig.Groups {
		if group.Mapping != nil {
			for mname, m := range group.Mapping {
				if m.Mode == ExecMode {
					continue
				}
				m.root, err = os.OpenRoot(m.Path)
				if err != nil {
					log.Error("Failed to open root for group mapping %s: %v", mname, err)
					group.Mapping[mname] = nil
				}
			}
		}
	}

	// Process users
	for login, user := range newConfig.Users {
		// Save old credentials if needed
		if s.config != nil && s.config.Users != nil {
			if oldUser, ok := s.config.Users[login]; ok {
				// Password
				if user.Password == "" {
					user.Password = oldUser.Password
					user.password = oldUser.password
					if user.password != "" && user.Password == "" {
						user.Password = s.secure.Encrypt(user.password)
					}

				 } else if user.Password == "-" { // Remove password when set to "-"
					user.Password = ""
					user.password = ""
				}
				 // Public key
				if user.PubKey == "" {
					user.PubKey = oldUser.PubKey
					user.pubkey = oldUser.pubkey
					if user.pubkey != "" && user.PubKey == "" {
						user.PubKey = s.secure.Encrypt(user.pubkey)
					}
				}
			}
		}

		// Skip empty users
		if user.Password == "" && user.PubKey == "" {
			log.Error("User %s has neither password nor pubkey, skipping", login)
			continue
		}

		// Parse user filters
		user.Filter.whitelist = parseIPNetList(user.Filter.Whitelist)
		user.Filter.blacklist = parseIPNetList(user.Filter.Blacklist)

		var groupNames []string
		groupNamesRaw := strings.Split(user.Groups, ",")
		seen := make(map[string]struct{})

		for _, groupName := range groupNamesRaw {
			groupName = strings.TrimSpace(groupName)
			if groupName == "" {
				continue
			}
			if _, exists := seen[groupName]; exists {
				continue
			}
			seen[groupName] = struct{}{}
			groupNames = append(groupNames, groupName)
		}

		// Create a new mapping for runtime that's independent from config Mapping
		user.mapping = make(map[string]*Mapping)

		for _, groupName := range groupNames {
			group, ok := newConfig.Groups[groupName]
			if !ok {
				log.Error("User %s references unknown group %s, ignoring", login, groupName)
				continue
			}
			// merge filters
			user.Filter.whitelist = mergeIPNetLists(user.Filter.whitelist, group.Filter.whitelist)
			user.Filter.blacklist = mergeIPNetLists(user.Filter.blacklist, group.Filter.blacklist)

			// merge mappings
			if group.Mapping != nil {
				for mname, m := range group.Mapping {
					if m.Mode == ExecMode || (m != nil && user.mapping[mname] == nil) {
						mCopy := *m
						user.mapping[mname] = &mCopy
					}
				}
			}
		}

		// Copy user's own mappings after merging from groups
		if user.Mapping != nil {
			for mname, m := range user.Mapping {
				mCopy := *m
				if m.Mode != ExecMode {
					mCopy.root, err = os.OpenRoot(m.Path)
					if err != nil {
						log.Error("Failed to open root for mapping %s: %v", mname, err)
						continue
					}
				}
				user.mapping[mname] = &mCopy
			}
		}

		 // Encrypt/decrypt password
		if user.Password != "" && !s.secure.IsEncrypted(user.Password) {
			user.Password = s.secure.Encrypt(user.Password)
		}

		if user.Password != "" {
			if dec, err := s.secure.Decrypt(user.Password); err == nil {
				user.password = dec
			}
		}

		 // Encrypt/decrypt public key and build fingerprint map
		if user.PubKey != "" && !s.secure.IsEncrypted(user.PubKey) {
			user.PubKey = s.secure.Encrypt(user.PubKey)
		}

		if user.PubKey != "" {
			if dec, err := s.secure.Decrypt(user.PubKey); err == nil {
				user.pubkey = dec
			} else {
				user.pubkey = user.PubKey
			}
			data := strings.TrimSpace(user.pubkey)

			if key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(data)); err == nil {
				fp := ssh.FingerprintSHA256(key)
				s.userPubKeyMap[fp] = user

			} else {
				log.Error("Failed to parse public key for user %s: %v", login, err)
			}
		}
		user.login = login
	}

	// Replace the entire configuration
	s.config = newConfig
	// log.Dump(newConfig)

	s.saveConfig()

	// Drop all current sessions
	if s.sessions != nil {
		for _, sessions := range s.sessions {
			for conn := range sessions {
				conn.Close()
			}
		}
	}
	return nil
}

// saveConfig writes the current config to the config file in JSON format.
func (s *SFTPD) saveConfig() {
	f, err := os.OpenFile(s.configFile, os.O_WRONLY | os.O_CREATE | os.O_TRUNC, 0600)
	if (err != nil) {
		log.Error("Failed to open config file for writing: %v", err)
		return
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "    ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(s.config); err != nil {
		log.Error("Failed to encode config: %v", err)
	}
	os.Chown(s.configFile, int(s.config.UID), int(s.config.GID))
}

// ExportConfig writes the current config to writer with decrypted private key and empty passwords.
func (s *SFTPD) ExportConfig(writer io.Writer) (err error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	exportConfig := s.config

	for login, user := range exportConfig.Users {
		orig := s.config.Users[login]
		if orig != nil {
			// shallow copy to avoid mutating the original User struct
			u := *user
			u.Password = "" // do not export password
			u.PubKey = ""   // do not export public key
			exportConfig.Users[login] = &u
		}
	}

	if s.config.private != "" {
		exportConfig.Private = s.config.private
	}

	if s.config.HTTP.url != "" {
		exportConfig.HTTP.URL = s.config.HTTP.url
	}

	if s.config.HTTP.Username != "" {
		exportConfig.HTTP.Username, err = s.secure.Decrypt(s.config.HTTP.Username)
		if err != nil {
			log.Error("Failed to decrypt HTTP username: %v", err)
		}
	}

	// Never pass the password to the web!
	exportConfig.HTTP.Password = ""

	enc := json.NewEncoder(writer)
	enc.SetIndent("", "    ")
	return enc.Encode(exportConfig)
}

// getUserByPassword returns a user by login and password (plaintext, after decryption).
func (s *SFTPD) getUserByPassword(login, password string) *User {
    s.mutex.Lock()
    user, ok := s.config.Users[login]
    s.mutex.Unlock()

    if !ok || user.password == "" || user.password != password {
        return nil
    }
    return user
}

// getUserByPublicKey returns a user by SSH public key fingerprint.
func (s *SFTPD) getUserByPublicKey(pubKey *ssh.PublicKey) *User {
	fp := ssh.FingerprintSHA256(*pubKey)

	s.mutex.Lock()
	user, ok := s.userPubKeyMap[fp]
	s.mutex.Unlock()

	if !ok {
		return nil
	}
	return user
}

// getUserByLogin returns a user by login from the current config.
func (s *SFTPD) getUserByLogin(login string) *User {
	s.mutex.Lock()
	user, ok := s.config.Users[login]
	s.mutex.Unlock()

	if !ok {
		return nil
	}
	return user
}

// parseIPNetList parses a CSV string of IP/CIDR values into []net.IPNet.
// If the string is empty, return an empty slice.
func parseIPNetList(list string) []net.IPNet {
	if list == "" {
		return nil
	}
	var out []net.IPNet
	for _, s := range strings.Split(list, ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if !strings.Contains(s, "/") {
			ip := net.ParseIP(s)
			if ip == nil {
				log.Error("Invalid IP: %s", s)
				continue
			}
			bits := 128
			if ip.To4() != nil {
				bits = 32
			}
			s = fmt.Sprintf("%s/%d", ip.String(), bits)
		}
		_, ipnet, err := net.ParseCIDR(s)
		if err != nil {
			log.Error("Invalid CIDR: %s (%v)", s, err)
			continue
		}
		out = append(out, *ipnet)
	}
	return out
}

// mergeIPNetLists adds elements from src to dst, avoiding duplicates.
func mergeIPNetLists(dst, src []net.IPNet) []net.IPNet {
	for _, s := range src {
		duplicate := false
		for _, d := range dst {
			if s.String() == d.String() {
				duplicate = true
				break
			}
		}
		if !duplicate {
			dst = append(dst, s)
		}
	}
	return dst
}

// processSecureField processes a secure field in the configuration.
func (s *SFTPD) processSecureField(jsonValue, runtimeValue *string, oldValue string) {
    // Decrypt if we have a value
    if *jsonValue != "" {
        if val, err := s.secure.Decrypt(*jsonValue); err == nil {
            *runtimeValue = val
        } else {
            *runtimeValue = *jsonValue
        }
    }

    // Use old value as fallback if needed
    if *runtimeValue == "" && oldValue != "" {
        *runtimeValue = oldValue
    }

    // Re-encrypt to ensure consistent storage
    if *runtimeValue != "" {
        *jsonValue = s.secure.Encrypt(*runtimeValue)
    }
}

