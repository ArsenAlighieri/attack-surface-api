﻿package models

import "gorm.io/gorm"

type Domain struct {
	gorm.Model
	UserID     uint
	Name       string `gorm:"type:varchar(255);uniqueIndex"` // 255 karakter uzunlukta varchar ve unique index
	Status     string `gorm:"type:varchar(20);default:'pending'"`
	Subdomains []Subdomain
}
