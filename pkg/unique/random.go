package unique

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"time"
)

// Token generates a random string token
func Token() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// GenerateUUID generates a Version 4 UUID using crypto/rand.
func GenerateUUID() string {
        uuid := make([]byte, 16)
        rand.Read(uuid)

        uuid[6] = (uuid[6] & 0x0f) | 0x40 // Set the version to 4 (randomly generated UUID)
        uuid[8] = (uuid[8] & 0x3f) | 0x80 // Set the variant to DCE 1.1 (two most significant bits are 10)

        return fmt.Sprintf("%x-%x-%x-%x-%x", uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:16])
}

// GenerateUUIDv7 generates a Version 7 UUID using crypto/rand.
func GenerateUUIDv7() string {
    uuid := make([]byte, 16)

    now := time.Now().UnixMilli()
    binary.BigEndian.PutUint64(uuid, uint64(now) << 16)

    rand.Read(uuid[6:])

    uuid[6] = 0x70 | (uuid[6] & 0x0F) // Version 7  (0x70)
    uuid[8] = 0x80 | (uuid[8] & 0x3F) // Variant 10 (0x80)

    return fmt.Sprintf("%x-%x-%x-%x-%x", uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:16])
}
