// Package middleware provides HTTP middleware for the crypto BFF.
package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// InternalJWTAuth validates internal JWT tokens for service-to-service auth.
func InternalJWTAuth(secret, audience string) gin.HandlerFunc {
	return func(c *gin.Context) {
		auth := c.GetHeader("Authorization")
		if auth == "" || !strings.HasPrefix(auth, "Bearer ") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": gin.H{"code": 90001, "message": "Autenticación requerida."},
			})
			return
		}

		tokenString := strings.TrimPrefix(auth, "Bearer ")
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, jwt.ErrSignatureInvalid
			}
			return []byte(secret), nil
		})

		if err != nil || !token.Valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": gin.H{"code": 90001, "message": "Token inválido."},
			})
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": gin.H{"code": 90001, "message": "Claims inválidos."},
			})
			return
		}

		// Validate audience
		aud, _ := claims.GetAudience()
		found := false
		for _, a := range aud {
			if a == audience {
				found = true
				break
			}
		}
		if !found {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": gin.H{"code": 90004, "message": "No tiene permisos para esta operación."},
			})
			return
		}

		c.Next()
	}
}

// SecurityHeaders adds security headers to responses.
func SecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Next()
	}
}

// RequestTimeout sets a request timeout header.
func RequestTimeout(seconds int) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Request-Timeout", strings.Repeat("1", seconds))
		c.Next()
	}
}
