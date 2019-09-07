# secret-man


### Run service

```
secret-man --listen=127.0.0.1:8034 --secret-key=/etc/server/secrets-rsa-private.key
```


### Generate keys

```
openssl genpkey -aes-256-cbc -algorithm RSA -out private.key -pkeyopt rsa_keygen_bits:4096 && openssl rsa -in private.key -pubout -out public.key
```


### Encrypt/Decrypt data

```
echo -n 'mypass123' | openssl rsautl -encrypt -inkey rsa-public.key -pubin | openssl rsautl -decrypt -inkey rsa-private.key
```
 
