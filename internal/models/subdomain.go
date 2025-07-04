package models

import "time"

type Subdomain struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	DomainID  uint      `json:"domain_id"`
	Name      string    `gorm:"unique;not null" json:"name"`
	CreatedAt time.Time `json:"created_at"`
}
