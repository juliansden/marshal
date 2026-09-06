/* Synthetic fixture: stub symbols matching the "openssl" signature markers in
 * fingerprint.go, without requiring a real OpenSSL install. Used to manually
 * exercise the BCA scan pipeline end-to-end. */
void SSL_CTX_new(void) {}
void OPENSSL_init_ssl(void) {}

int main(void) {
    return 0;
}
