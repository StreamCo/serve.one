Send a file with end-to-end encryption, inspired by https://encrypt.one, but something you can run locally.

# How does it work?

The file is encrypted before being served as a static file, and then decrypted in the recipient's browser

# Prerequisites

- [ngrok](https://ngrok.com/)

# Setup

Set `NGROK_AUTHTOKEN` in your environment.

To find where your authtoken is, run `ngrok config check`, and it should print out the config file location.

# Running

	NGROK_AUTHTOKEN=... go run github.com/streamco/serve.one@latest <filename>
