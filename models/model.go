package models

import (
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type HashEntries struct {
	gorm.Model
	ID         uuid.UUID `gorm:"type:uuid;primary_key;default:uuid_generate_v4()" json:"id"`
	PrefixHash string    `gorm:"unique; not null" json:"prefix_hash"`
	Index      uint      `gorm:"not null" json:"index"`
}
