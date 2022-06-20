package main

import (
	"github.com/Kong/go-pdk/server"
	"github.com/loafoe/kong-plugin-mtlsauth/auth"
)

func main() {
	_ = server.StartServer(auth.New, "0.1", 1000)
}
