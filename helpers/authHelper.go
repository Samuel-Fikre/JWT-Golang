package helper

import (
	"errors"

	"github.com/gin-gonic/gin"
)

// role string: This parameter is a string that represents the expected user role (like "USER", "ADMIN", etc.) that the function will check against.

func CheckUserType(c *gin.Context, role string) (err error) {
	userType := c.GetString("user_type")
	err = nil

	if userType != role {
		err = errors.New("unauthorized to access this resource")
		return err
	}
	return err
}

func MatchUserTypeToUid(c *gin.Context, userId string) (err error) {
	userType := c.GetString("user_type")
	uid := c.GetString("uid")
	err = nil

	// This check is important because it keeps users from seeing or interacting with other users' information.
	// For example, if you have a user named Alice with an ID of 1, and Bob (another user) tries to access Alice's information, the system will stop Bob because he is not allowed to see Alices data.

	if userType == "USER" && uid != userId {
		err = errors.New("unauthorized to access this resource")
	}
	err = CheckUserType(c, userType)
	return err
}
