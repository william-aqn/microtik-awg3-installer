package main

import (
	"errors"
	"regexp"
	"strings"
)

// Keep a bounded ASCII/POSIX subset for saved GeoSite expressions.
// Matching is performed in the container; unsupported syntax rejects the selection.
// Perl character classes below have the same meaning on ASCII DNS names.
func geoRegexp(pattern string) (string, error) {
	invalid := errors.New("Unsupported GeoSite regular expression")
	if len(pattern) == 0 || len(pattern) > 512 || strings.Contains(pattern, "(?") || strings.Contains(pattern, "[:") {
		return "", invalid
	}
	for _, modifier := range []string{"+?", "*?", "??", "}?"} {
		if strings.Contains(pattern, modifier) {
			return "", invalid
		}
	}
	for _, c := range pattern {
		if c < 32 || c > 126 {
			return "", invalid
		}
	}
	if _, e := regexp.Compile(pattern); e != nil {
		return "", invalid
	}
	var out strings.Builder
	inClass := false
	for i := 0; i < len(pattern); i++ {
		c := pattern[i]
		if c == '\\' {
			i++
			if i == len(pattern) {
				return "", invalid
			}
			c = pattern[i]
			// Preserve the normalized expression format used in USB snapshots.
			// DNS names use printable ASCII/Punycode.
			classes := map[byte]string{'d': "[0-9]", 'w': "[A-Za-z0-9_]", 's': "[ ]", 'D': "[^0-9]", 'W': "[^A-Za-z0-9_]", 'S': "[!-~]"}
			if replacement, ok := classes[c]; ok {
				if inClass {
					return "", invalid
				}
				out.WriteString(replacement)
			} else if strings.ContainsRune(`.\+*?()|[]{}^$-`, rune(c)) {
				out.WriteByte('\\')
				out.WriteByte(c)
			} else {
				return "", invalid
			}
			continue
		}
		if c == '[' {
			inClass = true
		}
		if c == ']' {
			inClass = false
		}
		out.WriteByte(c)
	}
	translated := out.String()
	if len(translated) > 768 {
		return "", invalid
	}
	if _, e := regexp.CompilePOSIX(translated); e != nil {
		return "", invalid
	}
	return translated, nil
}
