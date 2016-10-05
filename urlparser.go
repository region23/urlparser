package urlparser

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/PuerkitoBio/purell"
	"golang.org/x/net/idna"
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

	// если это относительный path вида somepage, то ничего не делаем и не парсим
	// может содержать буквы, цифры, знаки дефиса, точки
	isPrimitivePath, err := isPrimitivePath(rawURL)
	if err != nil {
		return nil, err
	}
	if isPrimitivePath {
		result := &URL{}
		result.Input = rawURL
		result.Relative = true
		result.Path = `./` + rawURL
		return result, nil

	}

	result := &URL{}
	result.Input = rawURL
	result.Scheme, result.DoubleSlash, result.Opaque, result.Query, result.Fragment = Split(rawURL)
	result.Authority, result.Path = splitAuthorityFromPath(result.Opaque)
	result.User, result.Host, result.Port = splitUserinfoHostPortFromAuthority(result.Authority)

	// Detect if this is relative URL or absolute
	if result.Scheme == "" && result.DoubleSlash == "" && result.Authority == "" && result.Port == "" {
		result.Relative = true
	}

	return result, nil

}

var (
	// RFC 1035.
	domainRegexp = regexp.MustCompile(`^([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]$`)
	ipv4Regexp   = regexp.MustCompile(`^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$`)
	ipv6Regexp   = regexp.MustCompile(`^\[[a-fA-F0-9:]+\]$`)
)

func isPrimitivePath(rawURL string) (bool, error) {
	return regexp.MatchString(`^[a-zA-Z0-9-.]*$`, rawURL)
}

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
		if strings.Index(matches["path"], "/") == -1 && strings.Index(matches["path"], "./") == -1 && strings.Index(matches["path"], "../") == -1 {
			matches["path"] = `./` + matches["path"]
		}
	}
	// ../somepath case
	if matches["authority"] == `..` || matches["authority"] == `.` {
		if strings.Index(matches["path"], "/") == 0 {
			matches["path"] = matches["authority"] + matches["path"]
			matches["authority"] = ""
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

// ToNetURL converts an urlparser.URL in to a net/url.URL
func (u *URL) ToNetURL() *url.URL {
	// FIXME users of net/url may expect most of these to be decoded
	host := ""
	if u.Host != "" {
		host = u.Host

		if u.Port != "" {
			host = fmt.Sprintf("%s:%s", host, u.Port)
		}
	}

	ret := &url.URL{
		Scheme: u.Scheme,
		//User: TODO
		Host:     host,
		Path:     u.Path,
		RawPath:  u.Path,
		RawQuery: u.Query,
		Fragment: u.Fragment,
	}

	if u.Authority == "" {
		ret.Opaque = u.Opaque
	}

	return ret
}

const normalizeFlags purell.NormalizationFlags = purell.FlagRemoveDefaultPort |
	purell.FlagDecodeDWORDHost | purell.FlagDecodeOctalHost | purell.FlagDecodeHexHost |
	purell.FlagRemoveUnnecessaryHostDots | purell.FlagRemoveDotSegments | purell.FlagRemoveDuplicateSlashes |
	purell.FlagUppercaseEscapes | purell.FlagDecodeUnnecessaryEscapes | purell.FlagEncodeNecessaryEscapes |
	purell.FlagSortQuery

// TODO Normalize NEED REALIZE
// Normalize returns normalized URL string.
// Behavior:
// 1. Remove unnecessary host dots.
// 2. Remove default port (http://localhost:80 becomes http://localhost).
// 3. Remove duplicate slashes.
// 4. Remove unnecessary dots from path.
// 5. Sort query parameters.
// 6. Decode host IP into decimal numbers.
// 7. Handle escape values.
// 8. Decode Punycode domains into UTF8 representation.
func (u *URL) Normalize() (string, error) {
	//var err error
	// Decode Punycode
	host, err := idna.ToUnicode(u.Host)
	if err != nil {
		return "", err
	}

	u.Host = strings.ToLower(host)
	u.Scheme = strings.ToLower(u.Scheme)

	netURL := u.ToNetURL()

	normalized := purell.NormalizeURL(netURL, normalizeFlags)
	//fmt.Println(normalized)
	return normalized, err
}

// NormalizeString returns normalized URL string.
// It's a shortcut for Parse() and Normalize() funcs.
// func NormalizeString(rawURL string) (string, error) {
// 	u, err := Parse(rawURL)
// 	if err != nil {
// 		return "", err
// 	}

// 	return u.Normalize()
// }

// RelToAbs transform relative path to absolute
// Received current site url & relative URL that need to stick
// func RelToAbs(currentURL, relativeURL string) *URL {

// }
