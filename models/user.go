package models

import (
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type User struct {
	UserID    uint64 `json:"user_id" gorm:"primaryKey"`
	FirstName string `json:"first_name" gorm:"not null" validate:"required"`
	LastName  string `json:"last_name" gorm:"not null" validate:"required"`
	UserName  string `json:"user_name" gorm:"not null"`
	DoB       string `json:"date_of_birth" gorm:"not null" validate:"required"`
	Gender    string `json:"gender" gorm:"not null;check gender IN('M','F','other')" validate:"required"`
	Email     string `json:"email" gorm:"not null;unique" validate:"required,email"`
	Phone     string `json:"phone" gorm:"not null;unique" validate:"required,len=10"`
	Role      string `json:"role" gorm:"not null;default:'user'"`
	Address   string `json:"address" gorm:"not null" validate:"required"`
	Password  string `json:"password" gorm:"not null" validate:"required"`
}

// CreateUser will create a user in the database
func (user *User) CreateUser(userr *User, db *gorm.DB) error {
	result := db.Create(&userr)
	if result.Error != nil {
		return result.Error
	}
	return nil
}

// FetchUser will get a user details from databse by email
func (user *User) FetchUser(val string, db *gorm.DB) (*User, error) {
	if err := db.Where("email = ?", val).First(&user).Error; err != nil {
		return nil, err
	}
	return user, nil
}

// UpdateUser function will update the user details
func (user *User) UpdateUser(db *gorm.DB) error {
	save := db.Save(&user)
	if save.Error != nil {
		return save.Error
	}
	return nil
}

// UpdateUSer will update the user
func UpdateUSer(user *User, db *gorm.DB) error {
	return user.UpdateUser(db)
}

// CheckPassword function will check the provided password with users password
func (user *User) CheckPassword(userr *User, providedPassword string) error {
	err := bcrypt.CompareHashAndPassword([]byte(userr.Password), []byte(providedPassword))
	if err != nil {
		return err
	}
	return nil
}

// HashPassword will hash the password of user
func (user *User) HashPassword(userr *User, password string) error {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	if err != nil {
		return err
	}
	userr.Password = string(bytes)
	return nil
}
