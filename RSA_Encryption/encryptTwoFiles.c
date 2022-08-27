#include <stdio.h>
#include <openssl/bn.h>

void printBN(char *msg, BIGNUM *a)
{
    char *number_str_a = BN_bn2hex(a);
    printf("%s %s\n", msg, number_str_a);
    OPENSSL_free(number_str_a);
}
int main()
{
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *n = BN_new();
    BIGNUM *d = BN_new();
    BIGNUM *message1 = BN_new();
    BIGNUM *message2 = BN_new();
    BIGNUM *C1 = BN_new();
    BIGNUM *C2 = BN_new();
    BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
    BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");
    BN_hex2bn(&message1, "49206f776520796f75202432303030"); 
    BN_hex2bn(&message2, "49206f776520796f75202433303030"); 
    BN_mod_exp(C1, message1, d, n, ctx);
    BN_mod_exp(C2, message2, d, n, ctx);
    printBN("Signature of message1:", C1);
    printBN("Signature of message2:", C2);
    BN_clear_free(n);
    BN_clear_free(d);
    BN_clear_free(message1);
    BN_clear_free(message2);
    BN_clear_free(C1);
    BN_clear_free(C2);
    return 0;
}