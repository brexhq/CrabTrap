package approval

import "regexp"

func globCacheLen() int {
	globCache.RLock()
	n := len(globCache.m)
	globCache.RUnlock()
	return n
}

func resetGlobCache() {
	globCache.Lock()
	globCache.m = make(map[string]*regexp.Regexp)
	globCache.Unlock()
}
