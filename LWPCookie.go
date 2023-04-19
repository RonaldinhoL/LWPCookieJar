package cookiejar

import (
	"net/http"
	"strings"
)

func (j *Jar) GetAllCookies() (cookies []*http.Cookie) {
	j.mu.Lock()
	defer j.mu.Unlock()
	for _, hostCookies := range j.entries {
		for _, entry := range hostCookies {
			cookies = append(cookies, entry.c)
		}
	}
	return cookies
}

func same_site_str_to_int(val string) (SameSite http.SameSite) {
	SameSite = http.SameSiteDefaultMode
	if len(val) == 0 {
		return
	}

	parts := strings.Split(val, "=")
	lowerVal := strings.ToLower(parts[1])
	switch lowerVal {
	case "lax":
		SameSite = http.SameSiteLaxMode
	case "strict":
		SameSite = http.SameSiteStrictMode
	case "none":
		SameSite = http.SameSiteNoneMode
	default:
		SameSite = http.SameSiteDefaultMode
	}
	return
}
