package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path"
	"sync"

	"golang.ngrok.com/ngrok"
	"golang.ngrok.com/ngrok/config"
)

func main() {
	if len(os.Args) <= 1 {
		log.Fatal("pls pass a filename")
	}
	filename := os.Args[1]
	contents, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Fatal(err)
	}
	if len(contents) < aes.BlockSize {
		padding := make([]byte, aes.BlockSize-len(contents))
		contents = append(contents, padding...)
	}
	log.Printf("encrypting %s...", filename)
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		panic(err.Error())
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}
	ciphertext := aesgcm.Seal(nil, nonce, contents, nil)
	var once sync.Once
	http.HandleFunc("/file/", func(w http.ResponseWriter, r *http.Request) {
		if hex.EncodeToString(nonce) != path.Base(r.URL.Path) {
			w.WriteHeader(http.StatusForbidden)
			io.WriteString(w, "wrong link")
			return
		}
		once.Do(func() {
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Write(ciphertext)
		})
	})
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `<p id="filename"></p>
<button onClick="doTheNeedful()">Download file</button>
<p id="error" style="color:red; font-weight:bold"></p>
<script>
        var qs = location.search.slice(1).split('&').reduce(function (params, next) {
                var keyval = next.split('=');
                params[keyval[0]] = keyval[1];
                return params;
        }, {});
function hex2a(hex) {
        var bytes = new Uint8Array(Math.ceil(hex.length / 2));
        for (var i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
        return bytes;
}
var nonce = hex2a(qs.nonce);
var keyData = hex2a(location.hash.slice(1));
document.getElementById('filename').innerHTML = qs.filename;

function doTheNeedful() {
        fetch('/file/' + qs.nonce).then(function (res) {
                if (res.status != 200) {
                        throw new Error('got status ' + res.status + ', secret link is invalid');
                }
                return res.arrayBuffer();
        }).then(function (encrypted) {
                if (encrypted.byteLength == 0) {
                        throw new Error('no data to read... secret is already expired/deleted :(');
                }
                return window.crypto.subtle.importKey(
                        "raw",
                        keyData,
                        {
                                name: "AES-GCM",
                        },
                        false,
                        ["decrypt"]
                ).then(function(key){
                        //returns the symmetric key
                        return window.crypto.subtle.decrypt(
                                {
                                        name: "AES-GCM",
                                        iv: nonce
                                },
                                key,
                                encrypted
                        );
                });
        }).then(function(data){
                var link = document.createElement('a');
                link.href = window.URL.createObjectURL(new Blob([new Uint8Array(data)]));
                link.download = qs.filename;
                link.click();
        }).catch(function(err){
                document.getElementById('error').innerHTML = err.message;
        });
}
</script>`)
	})
	ctx := context.Background()
	l, err := ngrok.Listen(ctx,
		config.HTTPEndpoint(),
		ngrok.WithAuthtokenFromEnv(),
	)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("https://%s/?filename=%s&nonce=%x#%x\n", l.Addr(), path.Base(filename), nonce, key)
	http.Serve(l, nil)
}
