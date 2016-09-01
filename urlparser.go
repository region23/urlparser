package urlparser

import (
	"regexp"
	"strings"
)

/*
   The generic URI syntax consists of a hierarchical sequence of
   components referred to as the scheme, authority, path, query, and
   fragment.

      URI         = scheme ":" hier-part [ "?" query ] [ "#" fragment ]

      hier-part   = "//" authority path-abempty
                  / path-absolute
                  / path-rootless
                  / path-empty

   The scheme and path components are required, though the path may be
   empty (no characters).  When authority is present, the path must
   either be empty or begin with a slash ("/") character.  When
   authority is not present, the path cannot begin with two slash
   characters ("//").  These restrictions result in five different ABNF
   rules for a path (Section 3.3), only one of which will match any
   given URI reference.

   The following are two example URIs and their component parts:

         foo://example.com:8042/over/there?name=ferret#nose
         \_/   \______________/\_________/ \_________/ \__/
          |           |            |            |        |
       scheme     authority       path        query   fragment
          |   _____________________|__
         / \ /                        \
         urn:example:animal:ferret:nose
*/

// The Userinfo type is an immutable encapsulation of username and
// password details for a URL. An existing Userinfo value is guaranteed
// to have a username set (potentially empty, as allowed by RFC 2396),
// and optionally a password.
type Userinfo struct {
	Username    string
	Password    string
	PasswordSet bool
}

// URL represents state for a parsed URL
type URL struct {
	Input  string
	Opaque string // encoded opaque

	Scheme      string
	DoubleSlash string
	// Elements of Authority
	User *Userinfo // username and password information
	Host string
	Port string
	// Elements of Opaque
	Authority string
	Path      string
	Query     string
	Fragment  string

	Relative bool // relative path?
}

// Parse parses raw URL string into the urlparser URL struct.
// It uses the url.Parse() internally, but it slightly changes
// its behavior:
// 1. It forces the default scheme and port.
// 2. It favors absolute paths over relative ones, thus "example.com"
//    is parsed into url.Host instead of url.Path.
// 4. It lowercases the Host (not only the Scheme).
func Parse(rawURL string) (*URL, error) {

	result := &URL{}
	result.Input = rawURL
	result.Scheme, result.DoubleSlash, result.Opaque, result.Query, result.Fragment = Split(rawURL)
	result.Authority, result.Path = splitAuthorityFromPath(result.Opaque)
	result.User, result.Host, result.Port = splitUserinfoHostPortFromAuthority(result.Authority)

	// Detect if this is relative URL or absolute

	return result, nil

}

var (
	// RFC 1035.
	domainRegexp = regexp.MustCompile(`^([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]$`)
	ipv4Regexp   = regexp.MustCompile(`^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$`)
	ipv6Regexp   = regexp.MustCompile(`^\[[a-fA-F0-9:]+\]$`)
)

// Split splits an URL in to its major components (scheme, opaque, query, fragment)
func Split(url string) (string, string, string, string, string) {
	parts := []string{
		"^(?P<firstgroup>(?P<scheme>[^:?/\\.]+):)?", // scheme is required by RFC3986 (S3) but we are intentionally allowing it to be omitted for convenience
		"(?P<doubleslash>(//)?)",                    // double slash after scheme
		"(?P<opaque>[^?#]+)?",                       // hier-part
		"(\\?(?P<query>[^#]+))?",                    // query
		"(#(?P<fragment>.*))?",                      // fragment
	}

	r := regexp.MustCompile(strings.Join(parts, ""))
	matches := namedMatches(r.FindStringSubmatch(url), r)

	// fix for `localhost` in scheme, because go regexp not support (?!badword) construction
	if matches["scheme"] == `localhost` {
		if matches["firstgroup"] == "localhost:" {
			matches["opaque"] = matches["firstgroup"] + matches["opaque"]
		} else {
			matches["opaque"] = matches["scheme"] + matches["opaque"]
		}
		matches["scheme"] = ""
	}

	return matches["scheme"], matches["doubleslash"], matches["opaque"], matches["query"], matches["fragment"]
}

func splitAuthorityFromPath(opaque string) (string, string) {
	r := regexp.MustCompile("(?P<authority>[^/]+)?(?P<path>/.*)?")
	matches := namedMatches(r.FindStringSubmatch(opaque), r)

	// fix for `.php .html .htm`
	if strings.Contains(matches["authority"], `.php`) || strings.Contains(matches["authority"], `.html`) || strings.Contains(matches["authority"], `.htm`) {
		matches["path"] = matches["authority"] + matches["path"]
		matches["authority"] = ""
		if strings.Index(matches["path"], "/") == -1 && strings.Index(matches["path"], "./") == -1 {
			matches["path"] = `./` + matches["path"]
		}
	}

	return matches["authority"], matches["path"]
}

func splitUserinfoHostPortFromAuthority(authority string) (*Userinfo, string, string) {
	userinfo := &Userinfo{}
	if delimPos := strings.LastIndex(authority, "@"); delimPos != -1 {
		uinfo := strings.Split(authority[0:delimPos], ":")
		if len(uinfo[0]) > 0 {
			userinfo.Username = uinfo[0]
		}
		if len(uinfo) > 1 && len(uinfo[1]) > 0 {
			userinfo.Password = uinfo[1]
			userinfo.PasswordSet = true
		} else {
			userinfo.PasswordSet = false
		}
		authority = authority[delimPos+1:]
	}

	parts := []string{
		"(", "(\\[(?P<host6>[^\\]]+)\\])", "|", "(?P<host>[^:]+)", ")?", // host6 | host
		"(:(?P<port>[0-9]+))?",
	}

	r := regexp.MustCompile(strings.Join(parts, ""))
	matches := namedMatches(r.FindStringSubmatch(authority), r)
	if matches["host"] == "" {
		matches["host"] = matches["host6"]
	}

	return userinfo, matches["host"], matches["port"]
}

// RFC3986: https://www.ietf.org/rfc/rfc3986.txt
// URI scheme registry: http://www.iana.org/assignments/uri-schemes/uri-schemes.xhtml
// TODO: Normalize method; See RFC3986 section 6.2.2 for normalization ref
func namedMatches(matches []string, r *regexp.Regexp) map[string]string {
	result := make(map[string]string)
	for i, name := range r.SubexpNames() {
		if name == "" {
			continue
		}
		if i >= len(matches) {
			result[name] = ""
		} else {
			result[name] = matches[i]
		}
	}
	return result
}
