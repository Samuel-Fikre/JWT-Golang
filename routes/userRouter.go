package routes

import (
	controller "jwtauthentication/controllers"
	middleware "jwtauthentication/middleware"

	"github.com/gin-gonic/gin"
)

// Define UserRoutes function that will attach user-related routes to the router
// his means that for every incoming request to any of the user-related routes (like /users and /users/:user_id), the Authenticate middleware will be executed first
func UserRoutes(incomingRoutes *gin.Engine) {
	incomingRoutes.Use(middleware.Authenticate())
	incomingRoutes.GET("/users", controller.GetUsers())
	incomingRoutes.GET("/users/:user_id", controller.GetUser())
}
