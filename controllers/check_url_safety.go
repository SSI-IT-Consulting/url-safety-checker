package controllers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/minodr/url-safety-checker.git/services"
	"github.com/minodr/url-safety-checker.git/utils"
	"github.com/pterm/pterm"
	"gorm.io/gorm"
)

func CheckURLSafety(db *gorm.DB, rdb *redis.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			URLs []string `json:"urls" binding:"required"`
		}

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, utils.GenerateErrorResponse(400, err.Error()))
			return
		}

		prefixes, err := services.GeneratePrefixHash(req.URLs)
		if err != nil {
			c.JSON(http.StatusInternalServerError, utils.GenerateErrorResponse(500, err.Error()))
			return
		}

		existsLocally, err := services.CheckIfHashExistsInCache(db, rdb, prefixes)
		if err != nil {
			c.JSON(http.StatusInternalServerError, utils.GenerateErrorResponse(500, err.Error()))
			return
		}

		response := make([]utils.Response, len(req.URLs))
		for i, full := range req.URLs {
			prefix := prefixes[full]
			if !existsLocally[prefix] {
				pterm.Warning.Println("safe prefix hashes found ...")
				response[i] = utils.GenerateSafeResponse(full)
			}
		}

		threatInfo := make(map[string]string)
		err = services.GetThreatInfoFromCache(rdb, req.URLs, threatInfo)
		if err != nil {
			c.JSON(http.StatusInternalServerError, utils.GenerateErrorResponse(500, err.Error()))
			return
		}

		var prefixesNotInCache []string
		for i, url := range req.URLs {
			if threatInfo[url] == "" && existsLocally[prefixes[url]] {
				prefixesNotInCache = append(prefixesNotInCache, prefixes[url])
			} else if threatInfo[url] != "" {
				pterm.Warning.Println("unsafe prefix hashes found in cache ...")
				response[i] = utils.GenerateUnsafeResponse(url, threatInfo[url])
			}
		}

		if len(prefixesNotInCache) > 0 {
			pterm.Warning.Println("fetching from google server ...")
			hashMatches, err := services.GetMatchingFullHashes(db, rdb, prefixesNotInCache)
			if err != nil {
				c.JSON(http.StatusInternalServerError, utils.GenerateErrorResponse(500, err.Error()))
				return
			}

			var unsafeURLs []string

			isSafe := services.CompareFullHashes(req.URLs, hashMatches)

			for i, url := range req.URLs {
				// If not already set by local or threat cache
				if response[i].URL == "" {
					if isSafe[url] {
						response[i] = utils.GenerateSafeResponse(url)
					} else {
						response[i].Status = "unsafe"
						unsafeURLs = append(unsafeURLs, url)
					}
				}
			}

			if len(unsafeURLs) > 0 {
				err = services.GetThreatInfoFromCache(rdb, unsafeURLs, threatInfo)
				if err != nil {
					c.JSON(http.StatusInternalServerError, utils.GenerateErrorResponse(500, err.Error()))
					return
				}
				// Assign threat types to newly unsafe URLs
				for i, url := range req.URLs {
					if response[i].Status == "unsafe" {
						response[i] = utils.GenerateUnsafeResponse(url, threatInfo[url])
					}
				}
			}
		}

		pterm.Success.Println("url safety check successful ...")
		c.JSON(http.StatusOK, response)
	}
}
