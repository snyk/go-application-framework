package file_filter

import "github.com/rs/zerolog"

const (
	MaxFileSize = 5000000 // 50 MB
)

var ignoredExtensionsGlob = []string{
	"*.bmp", "*.dcm", "*.gif", "*.iff",
	"*.jpg", "*.jpeg", "*.pbm", "*.pict",
	"*.pic", "*.pct", "*.pcx", "*.png",
	"*.psb", "*.psd", "*.pxr", "*.raw",
	"*.tga", "*.tiff", "*.svg",
}

var ignoreGenericFilesGlob = []string{
	// Go Modules & Build
	"go.mod",
	"go.sum",
	"go.work",
	"go.work.sum",
	// Go Vendor
	"vendor/modules.txt",
	"vendor/github.com/",
	"vendor/golang.org/x/",
	"vendor/google.golang.org/",
	"vendor/gopkg.in/",
	"vendor/istio.io/",
	"vendor/k8s.io/",
	"vendor/sigs.k8s.io/",
	// Node/JavaScript/General Web
	"node_modules/",
	"bower_components/",
	// Lockfiles
	"deno.lock",
	"npm-shrinkwrap.json",
	"package-lock.json",
	"pnpm-lock.yaml",
	"yarn.lock",
	// Vendored JS Libraries
	"angular*.js",
	"angular*.js.map",
	"bootstrap*.js",
	"bootstrap*.js.map",
	// Covers jquery and jquery-ui
	"jquery*.js",
	"jquery*.js.map",
	"plotly*.js",
	"plotly*.js.map",
	// Covers swagger-ui and swaggerui
	"swagger-ui*.js",
	"swagger-ui*.js.map",
	// Python Lockfiles
	"Pipfile.lock",
	"poetry.lock",
	// Virtual Envs
	"venv/lib/",
	"venv/lib64/",
	"env/lib/",
	"env/lib64/",
	"virtualenv/lib/",
	"virtualenv/lib64/",
	// System Libs
	"lib/python*/",
	"lib64/python*/",
	"python/*/lib/",
	"python/*/lib64/",
	// Dist Info
	"*.dist-info/",
	// Ruby
	"vendor/bundle/",
	"vendor/ruby/",
	"*.gem",
	// Java/Gradle/Maven
	"gradle.lockfile",
	"gradlew",
	"gradlew.bat",
	"mvnw",
	"mvnw.cmd",
	".mvn/wrapper/MavenWrapperDownloader.java",
	"verification-metadata.xml",
	// Configs & Metadata
	".git/",
	".gitleaks/",
	"gitleaks.toml",
	"javascript.json",
	"Database.refactorlog",
}

func NewSecretsFileFilter(path string, logger *zerolog.Logger) ([]Filterable, error) {
	ignoreRuleFiles := []string{".gitignore"}
	ignoreGlobs := ignoreGenericFilesGlob
	ignoreGlobs = append(ignoreGlobs, ignoredExtensionsGlob...)

	globFilter, err := NewIgnoresFileFilterFromGlobs(ignoreGlobs)
	if err != nil {
		return nil, err
	}

	ruleFilter, err := NewIgnoresFileFilterFromIgnoreFiles(path, ignoreRuleFiles, logger)
	if err != nil {
		return nil, err
	}

	textFileFilter := NewTextFileFilter(logger)

	sizeFileFilter := NewFileSizeFilter(logger, MaxFileSize)

	return []Filterable{sizeFileFilter, globFilter, ruleFilter, textFileFilter}, nil
}
