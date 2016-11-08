// Package easyssh provides a simple implementation of some SSH protocol
// features in Go. You can simply run a command on a remote server or get a file
// even simpler than native console SSH client. You don't need to think about
// Dials, sessions, defers, or public keys... Let easyssh think about it!
package easyssh

import (
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// Config contains ssh connection information.
// User field should be a name of user on remote server (ex. john in ssh john@example.com).
// Server field should be a remote machine address (ex. example.com in ssh john@example.com)
// Key is a path to private key on your local machine.
// Port is SSH server port on remote machine.
type Config struct {
	User     string
	Server   string
	Key      string
	Port     string
	Password string
}

func exists(path string) bool {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return false
	}
	return true
}

// returns ssh.Signer from user you running app home path + cutted key path.
// (ex. pubkey,err := getKeyFile("/.ssh/id_rsa") )
func getKeyFile(keypath string) (ssh.Signer, error) {
	file := keypath
	if !exists(file) {
		file = os.Getenv("HOME") + string(os.PathSeparator) + keypath
	}
	buf, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}
	pubkey, err := ssh.ParsePrivateKey(buf)
	if err != nil {
		return nil, err
	}

	return pubkey, nil
}

func getKeys() []string {
	sshHome := os.Getenv("HOME") + string(os.PathSeparator) + ".ssh"
	var keys []string
	candidates, _ := filepath.Glob(sshHome + string(os.PathSeparator) + "*")
	for _, k := range candidates {
		if k == "config" || strings.HasSuffix(k, ".pub") || k == "known_hosts" {
			continue
		}
		if !exists(k + ".pub") {
			continue
		}
		keys = append(keys, k)
	}
	return keys
}

// Connect to remote server using Config struct and return wrapped *ssh.Session
func (c *Config) Connect() (*ssh.Session, error) {
	// auths holds the detected ssh auth methods
	auths := []ssh.AuthMethod{}

	if strings.Contains(c.Server, "@") {
		toks := strings.Split(c.Server, "@")
		if len(toks) != 2 {
			return nil, fmt.Errorf("invalid server name: %s", c.Server)
		}
		c.Server, c.User = toks[1], toks[0]
	}
	if strings.Contains(c.User, ":") {
		toks := strings.Split(c.User, ":")
		if len(toks) != 2 {
			return nil, fmt.Errorf("invalid user name: %s", c.User)
		}
		c.User, c.Password = toks[0], toks[1]
	}

	// figure out what auths are requested, what is supported
	if c.Password != "" {
		auths = append(auths, ssh.Password(c.Password))
	}

	if sshAgent, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK")); err == nil {
		auths = append(auths, ssh.PublicKeysCallback(agent.NewClient(sshAgent).Signers))
		defer sshAgent.Close()
	}
	if c.User == "" {
		c.User = os.Getenv("USER")
	}

	if c.Password == "" && c.Key == "" {
		for _, key := range getKeys() {
			if pubkey, err := getKeyFile(key); err == nil {
				auths = append(auths, ssh.PublicKeys(pubkey))
			}
		}

	} else if pubkey, err := getKeyFile(c.Key); err == nil {
		auths = append(auths, ssh.PublicKeys(pubkey))
	}

	config := &ssh.ClientConfig{
		User:    c.User,
		Auth:    auths,
		Timeout: 1000 * time.Hour,
	}

	client, err := ssh.Dial("tcp", c.Server+":"+c.Port, config)
	if err != nil {
		return nil, err
	}

	session, err := client.NewSession()
	if err != nil {
		return nil, err
	}

	return session, nil
}

// Session makes an ssh.Session look like an exec.Command
type Session struct {
	*ssh.Session
	command string
}

// Start starts the command running
func (s *Session) Start() error {
	return s.Session.Start(s.command)
}

type sc struct {
	io.Reader
}

// Close is a non op allowing sc to be a ReadCloser
func (s sc) Close() error {
	return nil
}

// StdoutPipe returns a ReadCloser with the output of the command.
func (s *Session) StdoutPipe() (io.ReadCloser, error) {
	p, err := s.Session.StdoutPipe()
	return sc{p}, err
}

// Command returns one channel that combines the stdout and stderr of the command
// as it is run on the remote machine, and another that sends true when the
// command is done. The sessions and channels will then be closed.
func (c *Config) Command(command string) (*Session, error) {
	// connect to remote host
	session, err := c.Connect()
	if err != nil {
		return nil, err
	}
	return &Session{session, command}, err
}
