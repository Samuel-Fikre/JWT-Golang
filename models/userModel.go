package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// Using pointers for fields in Go, especially in struct types like the one in your User model, offers several benefits:

// optional fields: for eg some fields like token , refresh token might not be always present in the response so we use pointers to avoid null values

// for memory efficiency: pointers in Go are more memory efficient than non-pointer fields.

type User struct {
	ID            primitive.ObjectID `bson:"_id"`                                          // MongoDB ObjectID
	First_name    *string            `json:"first_name" validate:"required,min=2,max=100"` // User's first name (required, length 2-100)
	Last_name     *string            `json:"last_name" validate:"required,min=2,max=100"`  // User's last name (required, length 2-100)
	Password      *string            `json:"Password" validate:"required,min=6"`           // User's password (required, min length 6)
	Email         *string            `json:"email" validate:"email,required"`              // User's email (required, valid email                                     // User's avatar (optional)
	Phone         *string            `json:"phone" validate:"required"`                    // User's phone number (required)
	Token         *string            `json:"token"`                                        // Token (optional)
	Refresh_Token *string            `json:"refresh_token"`
	// Refresh token (optional)
	User_type  *string   `json:"user_type" validate:"required,eq=ADMIN|eq=USER"` // User type (required, must be "ADMIN" or "USER")
	Created_at time.Time `json:"created_at"`                                     // Time of account creation
	Updated_at time.Time `json:"updated_at"`                                     // Time of last account update
	User_id    string    `json:"user_id"`                                        // Custom user identifier
}
