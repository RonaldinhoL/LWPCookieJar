package cookiejar

import (
	"encoding/json"
	"net/http"
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
	Key     string
	DefPath string
	Host    string
	Cookie  *http.Cookie
}

func (j *Jar) SerializeCookiesToStr() (string, error) {
	j.mu.Lock()
	defer j.mu.Unlock()

	items := make([]PersistenceItem, 0)
	for _, hostCookies := range j.entries {
		for _, entry := range hostCookies {
			items = append(items, PersistenceItem{
				Key:     entry.key,
				DefPath: entry.defPath,
				Host:    entry.host,
				Cookie:  entry.c,
			})
		}
	}

	if r, err := json.Marshal(items); err != nil {
		return "", err
	} else {
		return string(r), err
	}
}

func (j *Jar) DeserializeCookiesFromStr(cookiesStr string) (err error) {
	var items []PersistenceItem
	err = json.Unmarshal([]byte(cookiesStr), &items)

	if len(items) == 0 {
		return
	}

	j.mu.Lock()
	defer j.mu.Unlock()
	now := time.Now()

	modified := false
	for _, i := range items {
		key := i.Key
		submap := j.entries[key]
		host := i.Host
		defPath := i.DefPath
		cookie := i.Cookie

		e, remove, err := j.newEntry(cookie, now, defPath, host)
		if err != nil {
			continue
		}
		id := e.id()
		if remove {
			if submap != nil {
				if _, ok := submap[id]; ok {
					delete(submap, id)
					modified = true
				}
			}
			continue
		}
		if submap == nil {
			submap = make(map[string]entry)
		}

		if old, ok := submap[id]; ok {
			e.Creation = old.Creation
			e.seqNum = old.seqNum
		} else {
			e.Creation = now
			e.seqNum = j.nextSeqNum
			j.nextSeqNum++
		}
		e.LastAccess = now
		e.key = key
		submap[id] = e
		modified = true

		if modified {
			if len(submap) == 0 {
				delete(j.entries, key)
			} else {
				j.entries[key] = submap
			}
		}
	}
	return
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
