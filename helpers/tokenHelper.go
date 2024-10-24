package helper

import (
	"context"
	"fmt"
	"jwtauthentication/database"
	"log"
	"os"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

//jwt.StandardClaims is a struct provided by the github.com/dgrijalva/jwt-go package that includes standard fields defined by the JWT specification. These fields are commonly used for claims that can be found in a JWT token, such as:

//IssuedAt (iat): The time at which the token was issued.
//ExpiresAt (exp): The expiration time of the token.
//NotBefore (nbf): The time before which the token must not be accepted for processing.
// Subject (sub): The subject of the token (often the user ID).
// Audience (aud): The intended recipient(s) of the token.

// Embedding: By embedding jwt.StandardClaims, SignedDetails automatically gets all the fields from StandardClaims, allowing you to add custom claims (like Email, First_name, etc.) alongside standard ones without redefining them.

type SignedDetails struct {
	Email      string
	First_name string
	Last_name  string
	Uid        string
	User_type  string
	jwt.StandardClaims
}

var userCollection *mongo.Collection = database.OpenCollection(database.Client, "user")

var SECRET_KEY string = os.Getenv("SECRET_KEY")

// Imagine you have a mobile app, and after logging in, the user receives this JWT token. The token contains their email, name, ID, and other important information. For security reasons, it expires in 24 hours, meaning the user will need to log in again or refresh the token after that time.

// see #JWT2282 for real life example how JWT is necessary

// Check out #JWT10018 it is good example of how JWT is used in real life

// Traditional Session-Based Authentication vs JWT Authentication #JWT201929

// For Refresh Token, the token expires in 168 hours (7 days), which is a longer duration. This means the user doesn't need to log in as frequently, but the token is still valid for a week. for more info check #120931j23mnmnad891a*

func GenerateAllTokens(email, firstName, lastName, userType, uid string) (signedToken string, signedRefreshToken string, err error) {
	claims := &SignedDetails{
		Email:      email,
		First_name: firstName,
		Last_name:  lastName,
		Uid:        uid,
		User_type:  userType,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Local().Add(time.Hour * time.Duration(24)).Unix(),
		},
	}

	refreshClaims := &SignedDetails{
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Local().Add(time.Hour * time.Duration(168)).Unix(),
		},
	}
	//jwt.SigningMethodHS256: This indicates that the HMAC SHA-256 signing algorithm is used to sign the token. It's a symmetric key algorithm, meaning the same key is used for both signing and verifying the token.

	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(SECRET_KEY))
	refreshToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims).SignedString([]byte(SECRET_KEY))

	if err != nil {
		log.Panic(err)
		return
	}

	return token, refreshToken, err
}

// &SignedDetails{}:

// This creates an empty SignedDetails object where the function will store the claims (like user ID, email, etc.) extracted from the JWT if it's valid.

func ValidateToken(signedToken string) (claims *SignedDetails, msg string, err error) {

	// This part is a function that helps the library know how to validate the JWT's signature.
	// It takes one input parameter, token, which is the JWT being parsed.
	// It returns two values:

	// Key (to check the signature): []byte(SECRET_KEY), which converts your secret key (probably a string) into a byte array.
	// Error: nil, meaning there's no error when getting the key.

	// Yes, the main purpose of the ValidateToken function is to check whether the provided string is a valid JWT and whether it meets certain criteria defined in the token's claims.

	// it checks if the token is a valid JWT (well-formed, properly signed, and not expired). While this validation does involve security aspects (like signature verification), it doesn't encompass broader security measures like user permissions or access control, which are usually handled elsewhere in the applicatio

	token, err := jwt.ParseWithClaims(signedToken, &SignedDetails{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(SECRET_KEY), nil
	})

	if err != nil {
		msg = err.Error()
		return
	}

	claims, ok := token.Claims.(*SignedDetails)
	if !ok {
		msg = fmt.Sprintf("the token is invalid")
		return
	}

	if claims.ExpiresAt < time.Now().Local().Unix() {
		msg = fmt.Sprintf("token is expired")
		return
	}

	return claims, msg, err
}

func UpdateAllTokens(signedToken string, signedRefreshToken string, userId string) {
	var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)

	defer cancel()

	var updateObj primitive.D

	updateObj = append(updateObj, bson.E{Key: "token", Value: signedToken})
	updateObj = append(updateObj, bson.E{Key: "refresh_token", Value: signedRefreshToken})

	updated_at, _ := time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))

	updateObj = append(updateObj, bson.E{Key: "updated_at", Value: updated_at})

	upsert := true
	filter := bson.M{"user_id": userId}

	opt := options.UpdateOptions{
		Upsert: &upsert,
	}

	_, err := userCollection.UpdateOne(
		ctx,
		filter,
		bson.D{{Key: "$set", Value: updateObj}},
		&opt,
	)

	if err != nil {
		log.Panic(err)
		return
	}

}
