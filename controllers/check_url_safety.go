package controllers

import (
	"context"
	"net/http"

	"github.com/SSI-IT-Consulting/url-safety-checker.git/services"
	"github.com/SSI-IT-Consulting/url-safety-checker.git/utils"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"
)

func CheckURLSafety(ctx context.Context, db *gorm.DB, rdb *redis.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			URLs []string `json:"urls" binding:"required"`
		}

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(400, utils.GenerateErrorResponse(400, err.Error()))
			return
		}

		response := make([]utils.Response, 0)

		safeSoFar, err := services.GetThreatInfoFromCache(ctx, rdb, req.URLs, &response)
		if err != nil {
			c.JSON(500, utils.GenerateErrorResponse(500, err.Error()))
			return
		}

		prefixes, err := services.GeneratePrefixHash(ctx, safeSoFar)
		if err != nil {
			c.JSON(500, utils.GenerateErrorResponse(500, err.Error()))
			return
		}

		safeUrls, unsafePrefixes, err := services.CheckIfPrefixExistsInDb(ctx, db, prefixes, safeSoFar)
		if err != nil {
			c.JSON(500, utils.GenerateErrorResponse(500, err.Error()))
			return
		}

		for _, url := range safeUrls {
			response = append(response, utils.GenerateSafeResponse(url))
		}

		matchingHashes := make(map[string]string)
		if len(unsafePrefixes) > 0 {
			matchingHashes, err = services.GetMatchingFullHashes(ctx, db, rdb, unsafePrefixes)
			if err != nil {
				c.JSON(500, utils.GenerateErrorResponse(500, err.Error()))
				return
			}
		}

		for _, fullHash := range unsafePrefixes {
			threatInfo, isThreat := matchingHashes[fullHash]
			if isThreat {
				response = append(response, utils.GenerateUnsafeResponse(fullHash, threatInfo))
			} else {
				response = append(response, utils.GenerateSafeResponse(fullHash))
			}
		}

		c.JSON(http.StatusOK, response)
	}
}
