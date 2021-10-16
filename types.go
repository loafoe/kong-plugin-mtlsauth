package main

import "time"

type mapperRequest struct {
	TPMHash      string `json:"tpm_hash"`
	DeviceSerial string `json:"device_serial"`
}

type mapperResponse struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	TokenType    string    `json:"token_type"`
	ExpiresIn    int       `json:"expires_in"`
	ExpiresAt    time.Time `json:"-"`
}
