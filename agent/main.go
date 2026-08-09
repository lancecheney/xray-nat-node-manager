package main

import (
	"flag"
	"fmt"
	"log"
	"os"
)

const version = "0.1.2"

func main() {
	configPath := flag.String("config", "/etc/xui-agent/config.json", "agent configuration file")
	adopt := flag.Bool("adopt", false, "adopt configured Xray inbounds into agent state and exit")
	check := flag.Bool("check", false, "validate agent and Xray configuration and exit")
	flag.Parse()

	cfg, err := loadConfig(*configPath)
	if err != nil {
		log.Fatal(err)
	}
	manager, err := newManager(cfg)
	if err != nil {
		log.Fatal(err)
	}

	switch {
	case *adopt:
		if err := manager.adopt(); err != nil {
			log.Fatal(err)
		}
		fmt.Printf("adopted %d inbound(s)\n", len(manager.snapshot().Inbounds))
	case *check:
		if err := manager.check(); err != nil {
			log.Fatal(err)
		}
		fmt.Println("configuration is valid")
	default:
		server := newAPIServer(cfg, manager)
		log.Printf("xui-agent %s listening on %s", version, cfg.Listen)
		if err := server.listenAndServe(); err != nil {
			log.Println(err)
			os.Exit(1)
		}
	}
}
