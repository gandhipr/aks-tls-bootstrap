package server

import (
	"time"
)

const JWKS_REFRESH_INTERVAL = 1 * time.Hour
const NONCE_EXPIRATION_CHECK_INTERVAL = 1 * time.Minute
const NONCE_LIFETIME = 30 * time.Second
const TOKEN_LIFETIME = 30 * time.Second
