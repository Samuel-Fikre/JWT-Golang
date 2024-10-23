package routes

import (
	controller "jwtauthentication/controllers"
	middleware "jwtauthentication/middleware"

	"github.com/gin-gonic/gin"
)

// Define UserRoutes function that will attach user-related routes to the router
func UserRoutes(incomingRoutes *gin.Engine) {
	incomingRoutes.Use(middleware.Authenticate())
	incomingRoutes.GET("/users/:user_id", controller.GetUser())
	incomingRoutes.POST("/users/signup", controller.SignUp())
	incomingRoutes.POST("/users/login", controller.Login())
}
