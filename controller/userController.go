package controllers

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"
	"strconv"

	"github.com/go-playground/validator/v10"
	helper "jwtauthentication/helpers"
	"jwtauthentication/models"
 	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/database"
	"golang.org/x/crypto/bcrypt"
)

var userCollection *mongo.Collection = database.OpenCollection(database.Client, "user")

var validate = validator.New()

// A hash is a one-way function that takes an input (your password) and produces a very random looking output. With the same input password, you get the same output, but if you change the input even a tiny amount, the output becomes wildly different. And you can't work backwards from the hash and derive the password.

When you sign up for the website, the website hashes your password and puts the hash in the database and discards the plain text password. When you come back later and log in with your password again, the server hashes the password you provided and then checks that the hash matches the one in the database. The server doesn't know your password but it can know that you know because the hashes match.

func HashPassword(password string) string {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	if err != nil {
		log.Panic(err)
	}
	return string(bytes)
}

func VerifyPassword(userPassword string, providedPassword string) (bool, string) {
	err := bcrypt.CompareHashAndPassword([]byte(providedPassword), []byte(userPassword))
	check := true
	msg := ""

	if err != nil {
		msg = "email or password is incorrect"
		check = false
	}
	return check, msg
}	

func Login() gin.HandlerFunc{
	return func(c *gin.Context){
    var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
		var user models.User
		var foundUser models.User

		if err := c.BindJSON(&user); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		defer cancel()

		err := userCollection.FindOne(ctx, bson.M{"email": user.Email}).Decode(&foundUser)
		defer cancel()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "email or password is incorrect"})
			return
		}

		passwordIsValid, msg := VerifyPassword(*user.Password, *foundUser.Password)
		defer cancel()
		if passwordIsValid != true {
			c.JSON(http.StatusInternalServerError, gin.H{"error": msg})
			return
		}

		if foundUser.Email == nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "user not found"})
		}

	}
}

func SignUp() gin.HandlerFunc {
	return func(c *gin.Context) {
		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
		defer cancel()
		var user models.User

	 if err := c.BindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	 }

	 validationErr := validate.Struct(user)
	 if validationErr != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": validationErr.Error()})
		return
	 }
  

	 // this checks if the email already exists in the database

	 // CountDocuments is used to count the number of documents that match the query criteria. then the count wouldnt be nil
	 countEmail, err := userCollection.CountDocuments(ctx, bson.M{"email": user.Email})
	 defer cancel()
	 if err != nil {
		log.Panic(err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "error occured while checking for the document"})
	 }

	 password := HashPassword(*user.Password)

	 user.Password = &password

	 countPhone, err := userCollection.CountDocuments(ctx, bson.M{"phone": user.Phone})
	 defer cancel()
	 if err != nil {
		log.Panic(err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "error occured while checking for the document"})

	 }

	 if countEmail > 0 && countPhone > 0 {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "this email or phone number already exists"})
	 }

	 // The token is created even after sign-up (even if the user isnt logged in immediately) for a few reasons,  Check #JWT00198#

	 user.Created_at, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
	 user.Updated_at, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
	 user.ID = primitive.NewObjectID()
	 user.User_id = user.ID.Hex()
	 token, refreshToken,_ := helper.GenerateAllTokens(*user.Email, *user.First_name, *user.Last_name, *user.User_type,user.User_id)
	 user.Token = &token
	 user.Refresh_Token = &refreshToken

	 resultInsertionNumber, insertErr := userCollection.InsertOne(ctx, user)
	 if insertErr != nil {
		log.Panic(insertErr)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "user was not created"})
	 }

	 defer cancel()
	 c.JSON(http.StatusOK, resultInsertionNumber)

	}
}


// The GetUser function can be used by both admins and regular users, but it is designed with certain checks to ensure that users can only access their own information

// If an admin calls this endpoint and they have a different user type (like "ADMIN"), they can access any user's information without restriction.

// In a real-life web application, when a user wants to view their profile or the profile of another user, they typically do so by making a request to the server using a user ID

func GetUser() gin.HandlerFunc {
	return func(c *gin.Context) {
	  var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
	  defer cancel()

	  userId := c.Param("user_id")

		if err := helper.MatchUserTypeToUid(c, userId); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		var user models.User

		err := userCollection.FindOne(ctx, bson.M{"user_id": userId}).Decode(&user)
		defer cancel()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, user)
	}
}	
