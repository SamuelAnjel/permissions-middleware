package permissions_middleware

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"net/http"
	"strings"
)

type PermissionMap = map[string]map[string]string
type MiddlewareConfig struct {
	RoutePermissions PermissionMap
	AllowUndefined   bool
}

func NewPermissionMiddleware(config MiddlewareConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		path := c.FullPath()
		method := c.Request.Method

		if permissionsForRoute, exists := config.RoutePermissions[path]; exists {
			requiredPermission, methodExists := permissionsForRoute[method]
			if !methodExists {
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
					"error": fmt.Sprintf("Permiso no definido para la ruta con %s con el médtodo %s", path, method),
				})
				return
			}
			userPermissions := c.GetHeader("X-User-Permissions")
			if userPermissions == "" {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
					"error": "No se proporcionaron permisos",
				})
				return
			}

			permissions := strings.Split(userPermissions, ",")
			if !hasPermission(permissions, requiredPermission) {
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
					"error": "no tienes permiso para acceder a este recurso y método",
				})
				return
			}
			c.Next()
			return
		}

		if config.AllowUndefined {
			c.Next()
			return
		}

		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
			"error": fmt.Sprintf("Ruta %s no definida en los permisos", path),
		})
	}
}

func hasPermission(userPermissions []string, requiredPermission string) bool {
	requiredParts := strings.Split(requiredPermission, ":")
	for _, permission := range userPermissions {
		if permission == "*:*" {
			return true
		}
		permissionParts := strings.Split(permission, ":")
		if len(permissionParts) == 2 {
			if permissionParts[0] == requiredParts[0] && permissionParts[1] == "*" {
				return true
			}
			if permissionParts[0] == "*" && permissionParts[1] == "*" {
				return true //refactor this redundancy
			}
			if permissionParts[0] == requiredParts[0] && permissionParts[1] == requiredParts[1] {
				return true
			}
		}
	}
	return false
}
