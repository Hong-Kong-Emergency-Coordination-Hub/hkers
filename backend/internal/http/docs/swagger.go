package docs

import (
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"
)

// OpenAPIInfo contains API metadata
type OpenAPIInfo struct {
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`
	Version     string `json:"version"`
}

// OpenAPIServer contains server information
type OpenAPIServer struct {
	URL         string `json:"url"`
	Description string `json:"description,omitempty"`
}

// OpenAPIOperation represents an API operation
type OpenAPIOperation struct {
	Summary     string                     `json:"summary,omitempty"`
	Description string                     `json:"description,omitempty"`
	OperationID string                     `json:"operationId,omitempty"`
	Tags        []string                   `json:"tags,omitempty"`
	Parameters  []OpenAPIParameter         `json:"parameters,omitempty"`
	Responses   map[string]OpenAPIResponse `json:"responses"`
}

// OpenAPIParameter represents a parameter
type OpenAPIParameter struct {
	Name        string        `json:"name"`
	In          string        `json:"in"`
	Description string        `json:"description,omitempty"`
	Required    bool          `json:"required"`
	Schema      OpenAPISchema `json:"schema"`
}

// OpenAPIResponse represents a response
type OpenAPIResponse struct {
	Description string `json:"description"`
}

// OpenAPISchema represents a schema
type OpenAPISchema struct {
	Type string `json:"type"`
}

// OpenAPIPathItem represents a path item with operations
type OpenAPIPathItem struct {
	Get    *OpenAPIOperation `json:"get,omitempty"`
	Post   *OpenAPIOperation `json:"post,omitempty"`
	Put    *OpenAPIOperation `json:"put,omitempty"`
	Patch  *OpenAPIOperation `json:"patch,omitempty"`
	Delete *OpenAPIOperation `json:"delete,omitempty"`
	Head   *OpenAPIOperation `json:"head,omitempty"`
}

// OpenAPISpec represents the OpenAPI specification
type OpenAPISpec struct {
	OpenAPI string                      `json:"openapi"`
	Info    OpenAPIInfo                 `json:"info"`
	Servers []OpenAPIServer             `json:"servers,omitempty"`
	Paths   map[string]*OpenAPIPathItem `json:"paths"`
}

// SwaggerConfig holds configuration for swagger generation
type SwaggerConfig struct {
	Title       string
	Description string
	Version     string
	BasePath    string
}

// DefaultSwaggerConfig returns default swagger configuration
func DefaultSwaggerConfig() SwaggerConfig {
	return SwaggerConfig{
		Title:       "HKERS API",
		Description: "HKERS Backend API - Auto-generated documentation",
		Version:     "1.0.0",
		BasePath:    "",
	}
}

var swaggerConfig = DefaultSwaggerConfig()

// SetSwaggerConfig sets the swagger configuration
func SetSwaggerConfig(cfg SwaggerConfig) {
	swaggerConfig = cfg
}

// GenerateOpenAPISpec generates OpenAPI spec from Gin router
func GenerateOpenAPISpec(router *gin.Engine, baseURL string) *OpenAPISpec {
	spec := &OpenAPISpec{
		OpenAPI: "3.0.3",
		Info: OpenAPIInfo{
			Title:       swaggerConfig.Title,
			Description: swaggerConfig.Description,
			Version:     swaggerConfig.Version,
		},
		Paths: make(map[string]*OpenAPIPathItem),
	}

	if baseURL != "" {
		spec.Servers = []OpenAPIServer{
			{URL: baseURL, Description: "Current server"},
		}
	}

	// Get all routes from Gin
	routes := router.Routes()

	for _, route := range routes {
		// Skip swagger routes themselves
		if strings.HasPrefix(route.Path, "/swagger") || strings.HasPrefix(route.Path, "/openapi") {
			continue
		}

		// Convert Gin path params (:id) to OpenAPI format ({id})
		openAPIPath := convertGinPathToOpenAPI(route.Path)

		// Get or create path item
		pathItem, exists := spec.Paths[openAPIPath]
		if !exists {
			pathItem = &OpenAPIPathItem{}
			spec.Paths[openAPIPath] = pathItem
		}

		// Create operation
		op := createOperation(route)

		// Assign operation to correct method
		switch route.Method {
		case "GET":
			pathItem.Get = op
		case "POST":
			pathItem.Post = op
		case "PUT":
			pathItem.Put = op
		case "PATCH":
			pathItem.Patch = op
		case "DELETE":
			pathItem.Delete = op
		case "HEAD":
			pathItem.Head = op
		}
	}

	return spec
}

// convertGinPathToOpenAPI converts Gin path format to OpenAPI format
// e.g., /users/:id -> /users/{id}
func convertGinPathToOpenAPI(path string) string {
	re := regexp.MustCompile(`:(\w+)`)
	return re.ReplaceAllString(path, "{$1}")
}

// extractPathParams extracts path parameters from Gin path
func extractPathParams(path string) []string {
	re := regexp.MustCompile(`:(\w+)`)
	matches := re.FindAllStringSubmatch(path, -1)
	params := make([]string, 0, len(matches))
	for _, match := range matches {
		if len(match) > 1 {
			params = append(params, match[1])
		}
	}
	return params
}

// extractTag extracts a tag from the route path
func extractTag(path string) string {
	// Remove leading slash and get first segment
	path = strings.TrimPrefix(path, "/")
	parts := strings.Split(path, "/")

	if len(parts) > 0 && parts[0] != "" {
		// Capitalize first letter
		tag := parts[0]
		if len(tag) > 0 {
			return strings.ToUpper(tag[:1]) + tag[1:]
		}
		return tag
	}
	return "Default"
}

// extractHandlerName extracts a clean handler name
func extractHandlerName(handler string) string {
	// Handler format is typically: hkers-backend/internal/http/handlers/auth.(*Handler).Login-fm
	// We want to extract: Login

	// Remove the -fm suffix if present
	handler = strings.TrimSuffix(handler, "-fm")

	// Get the last part after the last dot
	parts := strings.Split(handler, ".")
	if len(parts) > 0 {
		name := parts[len(parts)-1]
		// Remove pointer notation
		name = strings.TrimPrefix(name, "(*")
		name = strings.TrimSuffix(name, ")")
		return name
	}
	return handler
}

// generateOperationID creates a unique operation ID
func generateOperationID(method, path, handler string) string {
	handlerName := extractHandlerName(handler)
	if handlerName != "" && handlerName != "func1" {
		return strings.ToLower(method) + handlerName
	}

	// Fallback: use method + path
	cleanPath := strings.ReplaceAll(path, "/", "_")
	cleanPath = strings.ReplaceAll(cleanPath, ":", "")
	cleanPath = strings.ReplaceAll(cleanPath, "{", "")
	cleanPath = strings.ReplaceAll(cleanPath, "}", "")
	cleanPath = strings.Trim(cleanPath, "_")

	return strings.ToLower(method) + "_" + cleanPath
}

// createOperation creates an OpenAPI operation from a Gin route
func createOperation(route gin.RouteInfo) *OpenAPIOperation {
	handlerName := extractHandlerName(route.Handler)
	tag := extractTag(route.Path)

	op := &OpenAPIOperation{
		Summary:     formatSummary(handlerName, route.Method),
		OperationID: generateOperationID(route.Method, route.Path, route.Handler),
		Tags:        []string{tag},
		Responses: map[string]OpenAPIResponse{
			"200": {Description: "Successful response"},
			"400": {Description: "Bad request"},
			"401": {Description: "Unauthorized"},
			"500": {Description: "Internal server error"},
		},
	}

	// Add path parameters
	pathParams := extractPathParams(route.Path)
	for _, param := range pathParams {
		op.Parameters = append(op.Parameters, OpenAPIParameter{
			Name:        param,
			In:          "path",
			Description: formatParamDescription(param),
			Required:    true,
			Schema:      OpenAPISchema{Type: "string"},
		})
	}

	return op
}

// formatSummary creates a human-readable summary from handler name
func formatSummary(handlerName, method string) string {
	if handlerName == "" || handlerName == "func1" {
		return method + " operation"
	}

	// Convert CamelCase to spaces
	re := regexp.MustCompile(`([a-z])([A-Z])`)
	spaced := re.ReplaceAllString(handlerName, "$1 $2")

	return spaced
}

// formatParamDescription creates a description for a parameter
func formatParamDescription(param string) string {
	// Convert snake_case or camelCase to readable text
	param = strings.ReplaceAll(param, "_", " ")
	re := regexp.MustCompile(`([a-z])([A-Z])`)
	param = re.ReplaceAllString(param, "$1 $2")

	return "The " + strings.ToLower(param)
}

// OpenAPIHandler returns the OpenAPI JSON spec
func OpenAPIHandler(router *gin.Engine) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		// Build base URL from request
		scheme := "http"
		if ctx.Request.TLS != nil || ctx.GetHeader("X-Forwarded-Proto") == "https" {
			scheme = "https"
		}
		baseURL := scheme + "://" + ctx.Request.Host

		spec := GenerateOpenAPISpec(router, baseURL)
		ctx.JSON(200, spec)
	}
}

// SwaggerUIHandler serves the Swagger UI
func SwaggerUIHandler() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		html := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>` + swaggerConfig.Title + ` - API Documentation</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: system-ui, -apple-system, sans-serif; }
    </style>
</head>
<body>
    <script id="api-reference" data-url="/openapi.json"></script>
    <script src="https://cdn.jsdelivr.net/npm/@scalar/api-reference"></script>
</body>
</html>`
		ctx.Header("Content-Type", "text/html; charset=utf-8")
		ctx.String(200, html)
	}
}

// SwaggerUIClassicHandler serves the classic Swagger UI
func SwaggerUIClassicHandler() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		html := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>` + swaggerConfig.Title + ` - Swagger UI</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css">
    <style>
        body { margin: 0; padding: 0; }
        .swagger-ui .topbar { display: none; }
    </style>
</head>
<body>
    <div id="swagger-ui"></div>
    <script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
    <script>
        window.onload = () => {
            SwaggerUIBundle({
                url: "/openapi.json",
                dom_id: '#swagger-ui',
                deepLinking: true,
                presets: [
                    SwaggerUIBundle.presets.apis,
                    SwaggerUIBundle.SwaggerUIStandalonePreset
                ],
                layout: "BaseLayout"
            });
        };
    </script>
</body>
</html>`
		ctx.Header("Content-Type", "text/html; charset=utf-8")
		ctx.String(200, html)
	}
}

// RegisterSwaggerRoutes registers swagger documentation routes
func RegisterSwaggerRoutes(router *gin.Engine) {
	router.GET("/openapi.json", OpenAPIHandler(router))
	router.GET("/swagger", SwaggerUIHandler())
	router.GET("/swagger/classic", SwaggerUIClassicHandler())
}
