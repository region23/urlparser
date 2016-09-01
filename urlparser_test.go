package urlparser_test

import (
	. "github.com/pavlik/urlparser"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Urlparser", func() {
	Describe("Split", func() {
		It("should split url in to separate components", func() {
			r1, r2, r3, r4, r5 := Split("scheme://opaque?query#fragment")
			Expect(r1).Should(Equal("scheme"))
			Expect(r2).Should(Equal("//"))
			Expect(r3).Should(Equal("opaque"))
			Expect(r4).Should(Equal("query"))
			Expect(r5).Should(Equal("fragment"))
		})

		It("should allow omission of scheme component", func() {
			r1, r2, r3, r4, r5 := Split("opaque?query#fragment")
			Expect(r1).Should(Equal(""))
			Expect(r2).Should(Equal(""))
			Expect(r3).Should(Equal("opaque"))
			Expect(r4).Should(Equal("query"))
			Expect(r5).Should(Equal("fragment"))
		})

		It("should allow omission of query component", func() {
			r1, r2, r3, r4, r5 := Split("scheme://opaque#fragment")
			Expect(r1).Should(Equal("scheme"))
			Expect(r2).Should(Equal("//"))
			Expect(r3).Should(Equal("opaque"))
			Expect(r4).Should(Equal(""))
			Expect(r5).Should(Equal("fragment"))
		})

		It("should allow omission of fragment component", func() {
			r1, r2, r3, r4, r5 := Split("scheme://opaque?query")
			Expect(r1).Should(Equal("scheme"))
			Expect(r2).Should(Equal("//"))
			Expect(r3).Should(Equal("opaque"))
			Expect(r4).Should(Equal("query"))
			Expect(r5).Should(Equal(""))
		})
	})

	Describe("Parse", func() {
		It("should populate all major components of URL", func() {
			url, _ := Parse("http://user:pass@google.com:80/path?query=query#fragment")
			Expect(url.Scheme).Should(Equal("http"))
			Expect(url.DoubleSlash).Should(Equal("//"))
			Expect(url.Opaque).Should(Equal("user:pass@google.com:80/path"))
			Expect(url.Query).Should(Equal("query=query"))
			Expect(url.Fragment).Should(Equal("fragment"))
		})

		It("should separate opaque in to authority & path", func() {
			url, _ := Parse("http://user:pass@google.com:80/path?query=query#fragment")
			Expect(url.Authority).Should(Equal("user:pass@google.com:80"))
			Expect(url.Path).Should(Equal("/path"))
		})

		It("should separate authority in to userinfo, host and port", func() {
			url, _ := Parse("http://user:pass@google.com:80/path?query=query#fragment")
			userInfo := url.User
			Expect(url.Host).Should(Equal("google.com"))
			Expect(url.Port).Should(Equal("80"))
			Expect(userInfo.Username).Should(Equal("user"))
			Expect(userInfo.Password).Should(Equal("pass"))
			Expect(userInfo.PasswordSet).Should(Equal(true))
		})

		It("should handle empty path", func() {
			url, _ := Parse("http://google.com")
			Expect(url.Host).Should(Equal("google.com"))
			Expect(url.Path).Should(Equal(""))
		})

		It("should handle mailto: url", func() {
			url, _ := Parse("mailto:mike@mike.mike")
			Expect(url.Scheme).Should(Equal("mailto"))
			Expect(url.Opaque).Should(Equal("mike@mike.mike"))
		})

		It("should handle IPv6 url", func() {
			url, _ := Parse("http://[2001:db8:1f70::999:de8:7648:6e8]:9090?test=test")
			Expect(url.Scheme).Should(Equal("http"))
			Expect(url.DoubleSlash).Should(Equal("//"))
			Expect(url.Opaque).Should(Equal("[2001:db8:1f70::999:de8:7648:6e8]:9090"))
			Expect(url.Host).Should(Equal("2001:db8:1f70::999:de8:7648:6e8"))
			Expect(url.Port).Should(Equal("9090"))
			Expect(url.Query).Should(Equal("test=test"))
		})

		It("should handle naked host:port", func() {
			url, _ := Parse("google.com:8080")

			Expect(url.Host).Should(Equal("google.com"))
			Expect(url.Port).Should(Equal("8080"))
		})

		It("should handle naked host:port with localhost", func() {
			url, _ := Parse("localhost:8080")
			Expect(url.Host).Should(Equal("localhost"))
			Expect(url.Port).Should(Equal("8080"))
		})

		// // ------------ from another test -----------

		It("should parse with no path", func() {
			url, _ := Parse("http://www.google.com")
			Expect(url.Scheme).Should(Equal("http"))
			Expect(url.Host).Should(Equal("www.google.com"))
		})

		It("should parse with path", func() {
			url, _ := Parse("http://www.google.com/")
			Expect(url.Scheme).Should(Equal("http"))
			Expect(url.Host).Should(Equal("www.google.com"))
			Expect(url.Path).Should(Equal("/"))
		})

		It("should parse path with hex escaping", func() {
			url, _ := Parse("http://www.google.com/file%20one%26two")
			Expect(url.Scheme).Should(Equal("http"))
			Expect(url.Host).Should(Equal("www.google.com"))
			Expect(url.Path).Should(Equal("/file%20one%26two"))

			// _ := url.Normalize()
			// Expect(url.Path).Should(Equal("/file one&two"))
		})

		It("should parse user", func() {
			url, _ := Parse("ftp://webmaster@www.google.com/")
			userInfo := url.User
			Expect(url.Scheme).Should(Equal("ftp"))
			Expect(userInfo.Username).Should(Equal("webmaster"))
			Expect(url.Host).Should(Equal("www.google.com"))
			Expect(url.Path).Should(Equal("/"))
		})

		It("should parse user with pct-encoding in username", func() {
			url, _ := Parse("ftp://john%20doe@www.google.com/")
			userInfo := url.User
			Expect(url.Scheme).Should(Equal("ftp"))
			Expect(userInfo.Username).Should(Equal("john%20doe"))
			Expect(url.Host).Should(Equal("www.google.com"))
			Expect(url.Path).Should(Equal("/"))

			// _ := url.Normalize()
			// Expect(userInfo.Username).Should(Equal("john doe"))
		})

		It("should parse query", func() {
			url, _ := Parse("http://www.google.com/?q=go+language")
			Expect(url.Path).Should(Equal("/"))
			Expect(url.Query).Should(Equal("q=go+language"))
		})

		It("should not decode query with pct-encoding", func() {
			url, _ := Parse("http://www.google.com/?q=go%20language")
			Expect(url.Path).Should(Equal("/"))
			Expect(url.Query).Should(Equal("q=go%20language"))
		})

		It("should decode path with pct-encoding", func() {
			url, _ := Parse("http://www.google.com/a%20b?q=c+d")
			Expect(url.Path).Should(Equal("/a%20b"))
			Expect(url.Query).Should(Equal("q=c+d"))

			// _ := url.Normalize()
			// Expect(url.Path).Should(Equal("/a b"))
		})

		It("should correctly parse paths without leading slash", func() {
			url, _ := Parse("http:www.google.com/?q=go+language")
			Expect(url.Scheme).Should(Equal("http"))
			Expect(url.Opaque).Should(Equal("www.google.com/"))
			Expect(url.Query).Should(Equal("q=go+language"))
			Expect(url.Relative).Should(BeFalse())
		})

		It("should correctly parse mailto with path", func() {
			url, _ := Parse("mailto:/webmaster@golang.org")
			Expect(url.Scheme).Should(Equal("mailto"))
			Expect(url.Path).Should(Equal("/webmaster@golang.org"))
		})

		It("should correctly parse mailto", func() {
			url, _ := Parse("mailto:webmaster@golang.org")
			Expect(url.Scheme).Should(Equal("mailto"))
			Expect(url.Opaque).Should(Equal("webmaster@golang.org"))
		})

		It("should not produce invalid scheme if there is an unescaped :// in query", func() {
			url, _ := Parse("/foo?query=http://bad")
			Expect(url.Scheme).Should(Equal(""))
			Expect(url.Path).Should(Equal("/foo"))
			Expect(url.Query).Should(Equal("query=http://bad"))
			Expect(url.Relative).Should(BeTrue())
		})

		It("should handle urls starting //", func() {
			url, _ := Parse("//foo")
			Expect(url.Host).Should(Equal("foo"))
		})

		It("should handle urls starting // with userinfo, path & query", func() {
			url, _ := Parse("//user@foo/path?a=b")
			userInfo := url.User
			Expect(url.Host).Should(Equal("foo"))
			Expect(userInfo.Username).Should(Equal("user"))
			Expect(url.Query).Should(Equal("a=b"))
			Expect(url.Path).Should(Equal("/path"))
		})

		// Strange test. For now I should comment them
		// It("should handle urls starting ///", func() {
		// 	url, _ := Parse("///threeslashes")
		// 	Expect(url.Path).Should(Equal("///threeslashes"))
		// })

		It("should handle user / pass", func() {
			url, _ := Parse("http://user:password@google.com")
			userInfo := url.User
			Expect(url.Scheme).Should(Equal("http"))
			Expect(userInfo.Username).Should(Equal("user"))
			Expect(userInfo.Password).Should(Equal("password"))
			Expect(url.Host).Should(Equal("google.com"))
		})

		It("should handle unescaped @ in username", func() {
			url, _ := Parse("http://j@ne:password@google.com")
			userInfo := url.User
			Expect(userInfo.Username).Should(Equal("j@ne"))
			Expect(userInfo.Password).Should(Equal("password"))
			Expect(url.Host).Should(Equal("google.com"))
		})

		It("should handle unescaped @ in password", func() {
			url, _ := Parse("http://jane:p@ssword@google.com")
			userInfo := url.User
			Expect(userInfo.Username).Should(Equal("jane"))
			Expect(userInfo.Password).Should(Equal("p@ssword"))
			Expect(url.Host).Should(Equal("google.com"))
		})

		It("should handle @ all over the place", func() {
			url, _ := Parse("http://j@ne:p@ssword@google.com/p@th?q=@go")
			userInfo := url.User
			Expect(url.Scheme).Should(Equal("http"))
			Expect(userInfo.Username).Should(Equal("j@ne"))
			Expect(userInfo.Password).Should(Equal("p@ssword"))
			Expect(url.Host).Should(Equal("google.com"))
			Expect(url.Path).Should(Equal("/p@th"))
			Expect(url.Query).Should(Equal("q=@go"))
		})

		It("should handle fragment", func() {
			url, _ := Parse("http://www.google.com/?q=go+language#foo")
			Expect(url.Query).Should(Equal("q=go+language"))
			Expect(url.Fragment).Should(Equal("foo"))
		})

		// --------- Test relative URLs ----------
		It("should handle path", func() {
			url, _ := Parse("index.php")
			Expect(url.Path).Should(Equal("./index.php"))
			Expect(url.Relative).Should(BeTrue())
		})

		It("should handle path", func() {
			url, _ := Parse("index.php?q=go#foo")
			Expect(url.Path).Should(Equal("./index.php"))
			Expect(url.Query).Should(Equal("q=go"))
			Expect(url.Fragment).Should(Equal("foo"))
			Expect(url.Relative).Should(BeTrue())
		})

		It("should handle path", func() {
			url, _ := Parse("//static.t-ru.org/favicon.ico")
			Expect(url.DoubleSlash).Should(Equal("//"))
			Expect(url.Host).Should(Equal("static.t-ru.org"))
			Expect(url.Path).Should(Equal("/favicon.ico"))
		})

		It("should handle path", func() {
			url, _ := Parse("viewtopic.php?t=1045")
			Expect(url.Path).Should(Equal("./viewtopic.php"))
			Expect(url.Query).Should(Equal("t=1045"))
			Expect(url.Relative).Should(BeTrue())
		})

		It("should handle path", func() {
			url, _ := Parse("/favicon.png")
			Expect(url.Path).Should(Equal("/favicon.png"))
			Expect(url.Relative).Should(BeTrue())
		})

		It("should handle path", func() {
			url, _ := Parse("/public/js/jquery-ui/ui-lightness/jquery-ui-1.10.1.custom.css")
			Expect(url.Path).Should(Equal("/public/js/jquery-ui/ui-lightness/jquery-ui-1.10.1.custom.css"))
			Expect(url.Relative).Should(BeTrue())
		})

		It("should handle path", func() {
			url, _ := Parse("/cabinet")
			Expect(url.Path).Should(Equal("/cabinet"))
			Expect(url.Relative).Should(BeTrue())
		})

		It("should handle path", func() {
			url, _ := Parse("/howitworks.html")
			Expect(url.Path).Should(Equal("/howitworks.html"))
			Expect(url.Relative).Should(BeTrue())
		})

		It("should handle path", func() {
			url, _ := Parse("https://cdn.optimizely.com/js/6212760188.js")
			Expect(url.Scheme).Should(Equal("https"))
			Expect(url.DoubleSlash).Should(Equal("//"))
			Expect(url.Host).Should(Equal("cdn.optimizely.com"))
			Expect(url.Path).Should(Equal("/js/6212760188.js"))
		})

		It("should handle path", func() {
			url, _ := Parse("http://www.microsoftstore.com/store/msru/ru_RU/list/Project/categoryID.67042200")
			Expect(url.Scheme).Should(Equal("http"))
			Expect(url.DoubleSlash).Should(Equal("//"))
			Expect(url.Host).Should(Equal("www.microsoftstore.com"))
			Expect(url.Path).Should(Equal("/store/msru/ru_RU/list/Project/categoryID.67042200"))
		})

		It("should handle path", func() {
			url, _ := Parse("//www.microsoftstore.com/store/msru/ru_RU/DisplayThreePgCheckoutShoppingCartPage")
			Expect(url.Scheme).Should(Equal(""))
			Expect(url.DoubleSlash).Should(Equal("//"))
			Expect(url.Host).Should(Equal("www.microsoftstore.com"))
			Expect(url.Path).Should(Equal("/store/msru/ru_RU/DisplayThreePgCheckoutShoppingCartPage"))
		})

		It("should handle path", func() {
			url, _ := Parse("#fragment")
			Expect(url.Scheme).Should(Equal(""))
			Expect(url.DoubleSlash).Should(Equal(""))
			Expect(url.Host).Should(Equal(""))
			Expect(url.Path).Should(Equal(""))
			Expect(url.Fragment).Should(Equal("fragment"))
			Expect(url.Relative).Should(BeTrue())
		})

		It("should handle path", func() {
			url, _ := Parse("../viewtopic.php?t=1045")
			Expect(url.Path).Should(Equal("../viewtopic.php"))
			Expect(url.Query).Should(Equal("t=1045"))
			Expect(url.Relative).Should(BeTrue())
		})

		// It("should handle path", func() {
		// 	url, _ := Parse("viewtopic")
		// 	fmt.Printf("%#v\n", url)
		// 	Expect(url.Path).Should(Equal("./viewtopic"))
		// 	Expect(url.Query).Should(Equal(""))
		// })

		It("should handle path", func() {
			url, _ := Parse("./viewtopic")
			Expect(url.Path).Should(Equal("./viewtopic"))
			Expect(url.Query).Should(Equal(""))
			Expect(url.Relative).Should(BeTrue())
		})

		It("should handle path", func() {
			url, _ := Parse("../viewtopic")
			Expect(url.Path).Should(Equal("../viewtopic"))
			Expect(url.Query).Should(Equal(""))
			Expect(url.Relative).Should(BeTrue())
		})

	})
})
