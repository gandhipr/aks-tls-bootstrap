package server

import (
	"time"
)

const NONCE_EXPIRATION_CHECK_INTERVAL = 1 * time.Second
const NONCE_LIFETIME = 15 * time.Second
