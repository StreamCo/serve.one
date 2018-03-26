Send a file with end-to-end encryption, inspired by https://encrypt.one, but something you can run locally.

# How does it work?

The file is encrypted before being served as a static file, and then decrypted in the recipient's browser

Although ngrok is suggested so you can send files across the internet, you can ignore this and just use the IP address directly, for example within a corporate network.

# Setup

You'll need to get [ngrok](https://ngrok.com/) first if you want to send files over the internet.

# Running

    go run serveone.go <filename>

