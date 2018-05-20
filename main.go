package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"

	auth "github.com/abbot/go-http-auth"
	"github.com/buchgr/bazel-remote/cache"
	"github.com/buchgr/bazel-remote/server"
	"github.com/urfave/cli"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	yaml "gopkg.in/yaml.v2"
)

type config struct {
	host         string `yaml:"host"`
	port         int    `yaml:"port"`
	dir          string `yaml:"dir"`
	maxSize      int    `yaml:"max_size"`
	htpasswdFile string `yaml:"htpasswd_file"`
	tlsCertFile  string `yaml:"tls_cert_file"`
	tlsKeyFile   string `yaml:"tls_key_file"`
	remoteCache  *struct {
		host                      string `yaml:"host"`
		port                      int    `yaml:"port"`
		googleDefaultCredentials  bool   `yaml:"google_default_credentials"`
		googleCredentialsJSONFile string `yaml:"google_credentials_json_file"`
	} `yaml:"remote_cache"`
}

func parseConfig(ctx *cli.Context) (*config, error) {
	configFile := ctx.String("config_file")
	dir := ctx.String("dir")
	maxSize := ctx.Int("max_size")
	host := ctx.String("host")
	port := ctx.Int("port")
	htpasswdFile := ctx.String("htpasswd_file")
	tlsCertFile := ctx.String("tls_cert_file")
	tlsKeyFile := ctx.String("tls_key_file")

	if configFile != "" {
		file, err := os.Open(configFile)
		if err != nil {
			return nil, fmt.Errorf("Failed to open config file '%s': %v", configFile, err)
		}
		defer file.Close()

		data, err := ioutil.ReadAll(file)
		if err != nil {
			return nil, fmt.Errorf("Failed to read config file '%s': %v", configFile, err)
		}

		c := config{}
		err = yaml.Unmarshal(data, &c)
		if err != nil {
			return nil, fmt.Errorf("Failed to parse config file '%s': %v", configFile, err)
		}

		if c.dir == "" {
			return nil, fmt.Errorf("The 'dir' key is required in the YAML config")
		}

		if c.maxSize == 0 {
			return nil, fmt.Errorf("The 'max_size' key is required in the YAML config")
		}

		if (tlsCertFile != "" && tlsKeyFile == "") || (tlsCertFile == "" && tlsKeyFile != "") {
			return nil, fmt.Errorf("When enabling TLS, one must specify both keys " +
				"'tls_key_file' and 'tls_cert_file' in the YAML config")
		}

		return &c, nil
	}

	if dir == "" {
		return nil, fmt.Errorf("The 'dir' flag is required")
		return nil, cli.ShowAppHelp(ctx)
	}

	if maxSize < 0 {
		return nil, fmt.Errorf("The 'max_size' flag is required")
	}

	if (tlsCertFile != "" && tlsKeyFile == "") || (tlsCertFile == "" && tlsKeyFile != "") {
		return nil, fmt.Errorf("When enabling TLS, one must specify both flags " +
			"'tls_key_file' and 'tls_cert_file'")
	}

	return &config{
		host:         host,
		port:         port,
		dir:          dir,
		maxSize:      maxSize,
		htpasswdFile: htpasswdFile,
		tlsCertFile:  tlsCertFile,
		tlsKeyFile:   tlsKeyFile,
		remoteCache:  nil,
	}, nil
}

func main() {
	app := cli.NewApp()
	app.Description = "A remote build cache for Bazel."
	app.Usage = "A remote build cache for Bazel"
	app.HideHelp = true
	app.HideVersion = true

	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "config_file",
			Value: "",
			Usage: "Path to a YAML configuration file. If this flag is specified then all other flags " +
				"are ignored.",
			EnvVar: "BAZEL_REMOTE_CONFIG_FILE",
		},
		cli.StringFlag{
			Name:   "dir",
			Value:  "",
			Usage:  "Directory path where to store the cache contents. This flag is required.",
			EnvVar: "BAZEL_REMOTE_DIR",
		},
		cli.Int64Flag{
			Name:   "max_size",
			Value:  -1,
			Usage:  "The maximum size of the remote cache in GiB. This flag is required.",
			EnvVar: "BAZEL_REMOTE_MAX_SIZE",
		},
		cli.StringFlag{
			Name:   "host",
			Value:  "",
			Usage:  "Address to listen on. Listens on all network interfaces by default.",
			EnvVar: "BAZEL_REMOTE_HOST",
		},
		cli.IntFlag{
			Name:   "port",
			Value:  8080,
			Usage:  "The port the HTTP server listens on.",
			EnvVar: "BAZEL_REMOTE_PORT",
		},
		cli.StringFlag{
			Name:   "htpasswd_file",
			Value:  "",
			Usage:  "Path to a .htpasswd file. This flag is optional. Please read https://httpd.apache.org/docs/2.4/programs/htpasswd.html.",
			EnvVar: "BAZEL_REMOTE_HTPASSWD_FILE",
		},
		cli.BoolFlag{
			Name:   "tls_enabled",
			Usage:  "This flag has been deprecated. Specify tls_cert_file and tls_key_file instead.",
			EnvVar: "BAZEL_REMOTE_TLS_ENABLED",
		},
		cli.StringFlag{
			Name:   "tls_cert_file",
			Value:  "",
			Usage:  "Path to a pem encoded certificate file.",
			EnvVar: "BAZEL_REMOTE_TLS_CERT_FILE",
		},
		cli.StringFlag{
			Name:   "tls_key_file",
			Value:  "",
			Usage:  "Path to a pem encoded key file.",
			EnvVar: "BAZEL_REMOTE_TLS_KEY_FILE",
		},
	}

	app.Action = func(ctx *cli.Context) error {
		c, err := parseConfig(ctx)
		if err != nil {
			fmt.Fprintf(ctx.App.Writer, "%v\n\n", err)
			cli.ShowAppHelp(ctx)
			return nil
		}

		accessLogger := log.New(os.Stdout, "", log.Ldate|log.Ltime|log.LUTC)
		errorLogger := log.New(os.Stderr, "", log.Ldate|log.Ltime|log.LUTC)

		diskCache := cache.NewDiskCache(c.dir, int64(c.maxSize)*1024*1024*1024)
		cacheBackend := diskCache
		if c.remoteCache != nil {
			var remoteClient *http.Client
			var err error

			if c.remoteCache.googleDefaultCredentials {
				remoteClient, err = google.DefaultClient(oauth2.NoContext,
					"https://www.googleapis.com/auth/cloud-platform")
				if err != nil {
					log.Fatalf("Failed to instantiate Google Application Default Authentication: '%v'", err)
				}
			} else if c.remoteCache.googleCredentialsJSONFile != "" {
				jsonConfig, err := ioutil.ReadFile(c.remoteCache.googleCredentialsJSONFile)
				if err != nil {
					log.Fatalf("Failed to read Google Credentials file '%s': %v",
						c.remoteCache.googleCredentialsJSONFile, err)
				}

				config, err := google.CredentialsFromJSON(oauth2.NoContext, jsonConfig)
				if err != nil {
					log.Fatalf("The provided Google Credentials couldn't be parsed: %v", err)
				}

				remoteClient = oauth2.NewClient(oauth2.NoContext, config.TokenSource)
			} else {
				remoteClient = &http.Client{}
			}
			cacheBackend = cache.NewHTTPProxyCache(c.remoteCache.host, c.remoteCache.port, diskCache,
				remoteClient, accessLogger, errorLogger)
		}
		h := server.NewHTTPCache(cacheBackend, accessLogger, errorLogger)

		http.HandleFunc("/status", h.StatusPageHandler)
		http.HandleFunc("/", maybeAuth(h.CacheHandler, c.htpasswdFile, c.host))

		if len(c.tlsCertFile) > 0 && len(c.tlsKeyFile) > 0 {
			return http.ListenAndServeTLS(c.host+":"+strconv.Itoa(c.port), c.tlsCertFile,
				c.tlsKeyFile, nil)
		}
		return http.ListenAndServe(c.host+":"+strconv.Itoa(c.port), nil)
	}

	serverErr := app.Run(os.Args)
	if serverErr != nil {
		log.Fatal("ListenAndServe: ", serverErr)
	}
}

func maybeAuth(fn http.HandlerFunc, htpasswdFile string, host string) http.HandlerFunc {
	if htpasswdFile != "" {
		secrets := auth.HtpasswdFileProvider(htpasswdFile)
		authenticator := auth.NewBasicAuthenticator(host, secrets)
		return auth.JustCheck(authenticator, fn)
	}
	return fn
}
