package main

import (
	"flag"
	"log"
	"os"
	"os/exec"
	"os/signal"
	sftpd "sftp/internal"
	"strconv"
	"syscall"
)

func main() {
	if os.Getppid() != 1 {
		args := append([]string{os.Args[0]}, os.Args[1:]...)
		cmd := exec.Command(args[0], args[1:]...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Stdin  = os.Stdin
		cmd.Start()
		os.Exit(0)
	}

	configFile := flag.String("c", "/usr/local/etc/sftpd.conf", "Path to the configuration file")
	logFile    := flag.String("l", "/var/log/sftpd.log",        "Path to the log file")
	pidFile    := flag.String("p", "/run/sftpd.pid",            "Path to the PID file")
	flag.Parse()

	app, err := sftpd.New(*configFile, *logFile)
	if err != nil {
		log.Fatalf("Failed to initialize application: %v\n", err)
	}
	os.WriteFile(*pidFile, []byte(strconv.Itoa(os.Getpid())), 0644)
	app.Start() // drops privileges inside

	signalC := make(chan os.Signal, 16)
	signal.Notify(signalC, os.Interrupt, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)

	for {
		sig := <-signalC
		switch sig {
		case syscall.SIGHUP:
			app.LoadConfig()

		case syscall.SIGTERM, syscall.SIGINT, os.Interrupt, syscall.SIGQUIT:
			os.Exit(0)
		}
	}
}
