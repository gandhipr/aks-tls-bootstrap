package server

import (
	"time"
)

const NONCE_EXPIRATION_CHECK_INTERVAL = 1 * time.Minute
const NONCE_LIFETIME = 30 * time.Second
