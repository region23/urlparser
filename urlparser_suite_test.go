package urlparser_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"testing"
)

func TestUrlparser(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Urlparser Suite")
}
