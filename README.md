# easyssh

This fork automatically differs from its source in the following ways:
+ it tries all keys in ~/.ssh
+ handles a server like "user@server.com"
+ pulls a password from user:password@server.com
+ allows cross-compilation by using $USER instead of user.Current
+ it just supports Connect() and tries to match the interface of `*exec.Cmd`

## Description

Package easyssh provides a simple implementation of some SSH protocol features in Go.
You can simply run command on remote server or upload a file even simple than native console SSH client.
Do not need to think about Dials, sessions, defers and public keys...Let easyssh will be think about it!

## So easy to use!

[Run a command on remote server and get STDOUT output](https://github.com/hypersleep/easyssh/blob/master/example/run.go)

[Upload a file to remote server](https://github.com/hypersleep/easyssh/blob/master/example/scp.go)
