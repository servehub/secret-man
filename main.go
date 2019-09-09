package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	consulApi "github.com/hashicorp/consul/api"
	"github.com/servehub/utils/gabs"
	"github.com/youmark/pkcs8"
	"golang.org/x/crypto/ssh/terminal"
	"gopkg.in/alecthomas/kingpin.v2"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/render"
)

var version = "1.0"

func main() {
	secretKeyPath := kingpin.Flag("secret-key", "Path to secret key file").Required().String()
	consulAddress := kingpin.Flag("consul-address", "Consul address").Default("127.0.0.1:8500").String()
	consulPath := kingpin.Flag("consul-path", "Path to secrets in Consul KV").Default("services/secrets/").String()
	listen := kingpin.Flag("listen", "Addr to listen").Default("127.0.0.1:8042").String()

	kingpin.Version(version)
	kingpin.Parse()

	log.Print("Enter secret key password: ")
	keyPassword, termErr := terminal.ReadPassword(int(syscall.Stdin))
	kingpin.FatalIfError(termErr, "Error on read secret key: %v", termErr)

	privBytes, loadErr := ioutil.ReadFile(*secretKeyPath)
	kingpin.FatalIfError(loadErr, "Error on load secret key: %v", loadErr)

	privPem, _ := pem.Decode(privBytes)

	privateKey, parseErr := pkcs8.ParsePKCS8PrivateKeyRSA(privPem.Bytes, keyPassword)
	kingpin.FatalIfError(parseErr, "Error on parse secret key: %v", parseErr)

	cf := consulApi.DefaultConfig()
	cf.Address = *consulAddress
	consul, consulErr := consulApi.NewClient(cf)
	kingpin.FatalIfError(consulErr, "Error on connecting to consul: %v", parseErr)

	log.Printf("secret-man starting on %s...", *listen)

	r := chi.NewRouter()
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(render.SetContentType(render.ContentTypeJSON))

	r.Get("/secrets/*", func(w http.ResponseWriter, req *http.Request) {
		serviceName := "/" + chi.URLParam(req, "*")

		log.Printf("Get `%s` secrets", serviceName)

		allSecrets, _, listErr := consul.KV().List(*consulPath, nil)
		kingpin.FatalIfError(listErr, "Error on list all secrets from consul: %v", listErr)

		output := make(map[string]string)

		for _, item := range allSecrets {
			jsonData, jsonErr := gabs.ParseJSON(item.Value)
			kingpin.FatalIfError(jsonErr, "Error on parse json from consul: %v", jsonErr)

			secrets, _ := jsonData.Path("secrets").ChildrenMap()

			for secretName, secret := range secrets {
				if secret.ExistsP("target") {
					targets, _ := secret.Path("target").Children()

					for _, target := range targets {
						if strings.HasPrefix(serviceName, fmt.Sprintf("%s", target.Path("app").Data())) {
							output[secretName] = fmt.Sprintf("%s", secret.Path("value").Data())
							break
						}
					}
				} else {
					output[secretName] = fmt.Sprintf("%s", secret.Path("value").Data())
				}

				if encrypted, ok := output[secretName]; ok {
					if plaintext, err := decryptAes(encrypted, privateKey); err == nil {
						output[secretName] = plaintext
					} else {
						log.Printf("Error decrypt %s: %v", secretName, err)
						delete(output, secretName)
					}
				}
			}
		}

		body, _ := json.Marshal(output)
		_, _ = w.Write(body)
	})

	httpErr := http.ListenAndServe(*listen, r)
	kingpin.FatalIfError(httpErr, "Error on start secret-man server: %v", httpErr)

	ch := make(chan os.Signal)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM, syscall.SIGKILL)
	log.Println("secret-man shutdown by", <-ch)
}

func decryptAes(data string, privateKey *rsa.PrivateKey) (string, error) {
	b64Decoded, _ := base64.StdEncoding.DecodeString(data)

	if plain, err := privateKey.Decrypt(rand.Reader, b64Decoded, nil); err == nil {
		return string(plain), nil
	} else {
		return "", err
	}
}
