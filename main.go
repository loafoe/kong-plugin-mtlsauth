package main

import (
	"github.com/Kong/go-pdk/server"
	"github.com/loafoe/kong-plugin-mtlsauth/mtlsauth"
)

func main() {
	_ = server.StartServer(mtlsauth.New, "0.1", 1000)
}
