package cookiejar

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"
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

type PersistenceItem struct {
	// key 是在 cookieJar map 里面的 key
	Key                  string
	DefPath              string
	Host                 string
	Cookie               *http.Cookie
	U                    url.URL
	SessionCookieSetTime time.Time
	Domain               string
}

func (j *Jar) GetAllCookiesAsPersistenceItems() []PersistenceItem {
	j.mu.Lock()
	defer j.mu.Unlock()

	items := make([]PersistenceItem, 0)
	for _, hostCookies := range j.entries {
		for _, e := range hostCookies {
			cookie := e.c
			// remove MaxAge, becasue it has been add to Expires
			if cookie.MaxAge > 0 {
				// prefer original Expires
				if cookie.Expires.IsZero() {
					cookie.Expires = e.Expires
				}
				cookie.MaxAge = 0
			}
			items = append(items, PersistenceItem{
				Key:                  e.key,
				DefPath:              e.defPath,
				Host:                 e.host,
				Cookie:               cookie,
				U:                    e.u,
				SessionCookieSetTime: e.SessionCookieSetTime,
				Domain:               e.Domain,
			})
		}
	}
	return items
}

func (j *Jar) SerializeCookiesToItems() []PersistenceItem {
	items := j.GetAllCookiesAsPersistenceItems()
	return items
}

func (j *Jar) SerializeCookiesToStr() (string, error) {
	items := j.SerializeCookiesToItems()
	if r, err := json.Marshal(items); err != nil {
		return "", err
	} else {
		return string(r), err
	}
}

func (j *Jar) DeserializeCookiesFromItemsWithDuration(items []PersistenceItem, sessionCookieAliveDuration time.Duration) (err error) {
	if len(items) == 0 {
		return
	}
	for _, i := range items {
		// 这里要用指针，否则所有cookie都会指向同一个地址
		cookie := i.Cookie
		if cookie.RawExpires != "" {
			cookie.Expires, err = ParseDateString(cookie.RawExpires)
			if err != nil {
				return err
			}
		}
		if !cookie.Expires.IsZero() && time.Now().Sub(cookie.Expires) > 0 {
			// delete expired cookies
			continue
		}
		// check the session cookie if expired
		if !i.SessionCookieSetTime.IsZero() && sessionCookieAliveDuration > 0 {
			if time.Now().Sub(i.SessionCookieSetTime) > sessionCookieAliveDuration {
				continue
			} else {
				cookie.Expires = i.SessionCookieSetTime.Add(sessionCookieAliveDuration)
			}
		}
		j.SetCookies(&i.U, []*http.Cookie{
			cookie,
		})
	}
	return
}

func (j *Jar) DeserializeCookiesFromStr(cookiesStr string, sessionCookieAliveDuration time.Duration) (err error) {
	var items []PersistenceItem
	err = json.Unmarshal([]byte(cookiesStr), &items)
	if err != nil {
		return err
	}
	return j.DeserializeCookiesFromItemsWithDuration(items, sessionCookieAliveDuration)
}

func SameSiteStrToInt(val string) (SameSite http.SameSite) {
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

func SameSiteIntToStr(sameSite http.SameSite) string {
	switch sameSite {
	case http.SameSiteLaxMode:
		return "lax"
	case http.SameSiteStrictMode:
		return "strict"
	case http.SameSiteNoneMode:
		return "none"
	default:
		return ""
	}
}

func ParseDateString(dt string) (t time.Time, err error) {
	t, err = time.Parse("Mon, 02-Jan-2006 15:04:05 MST", dt)
	if err != nil {
		t, err = time.Parse("Mon, 02 Jan 2006 15:04:05 MST", dt)
	}
	if err != nil {
		// Fri, 17-May-24 03:22:24 GMT
		t, err = time.Parse("Mon, 02-Jan-06 15:04:05 MST", dt)
	}

	return
}
