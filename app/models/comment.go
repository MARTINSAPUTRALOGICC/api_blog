package models

import "time"

type Comment struct {
	ID         uint      `json:"id" gorm:"primaryKey"`
	PostID     uint      `json:"post_id" gorm:"not null;index"`
	AuthorName string    `json:"author_name" gorm:"type:varchar(255);not null"`
	Content    string    `json:"content" gorm:"type:text;not null"`
	CreatedAt  time.Time `json:"created_at"`

	Post BlogPost `json:"post,omitempty" gorm:"foreignKey:PostID"`
}
