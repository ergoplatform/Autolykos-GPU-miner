/* ------------------------------------------------------------ *
 * gcc -o eckeycreate eckeycreate.c -lssl -lcrypto              *
 * ------------------------------------------------------------ */

#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <stdio.h>

#define ECCTYPE    "secp256k1"

int main(
)
{

    BIO      *outbio = NULL;
    EC_KEY   *myecc  = NULL;
    EVP_PKEY *pkey   = NULL;
    int      eccgrp;

    // These function calls initialize openssl for correct work.
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();

    // Create the Input/Output BIO's.
    outbio  = BIO_new(BIO_s_file());
    outbio = BIO_new_fp(stdout, BIO_NOCLOSE);

    // Create a EC key sructure, setting the group type from NID
    eccgrp = OBJ_txt2nid(ECCTYPE);
    myecc = EC_KEY_new_by_curve_name(eccgrp);

    // For cert signing, we use  the OPENSSL_EC_NAMED_CURVE flag
    EC_KEY_set_asn1_flag(myecc, OPENSSL_EC_NAMED_CURVE);

    // Create the public/private EC key pair here
    if (!(EC_KEY_generate_key(myecc)))
        BIO_printf(outbio, "Error generating the ECC key.");

    // Converting the EC key into a PKEY structure let us
    // handle the key just like any other key pair.
    pkey=EVP_PKEY_new();
    if (!EVP_PKEY_assign_EC_KEY(pkey, myecc))
        BIO_printf(outbio, "Error assigning ECC key to EVP_PKEY structure.");

    // Now we show how to extract EC-specifics from the key
    myecc = EVP_PKEY_get1_EC_KEY(pkey);
    const EC_GROUP *ecgrp = EC_KEY_get0_group(myecc);

    /// original /// // Here we print the key length, and extract the curve type.
    /// original /// BIO_printf(outbio, "ECC Key size: %d bit\n", EVP_PKEY_bits(pkey));
    /// original /// BIO_printf(
    /// original ///     outbio, "ECC Key type: %s\n", OBJ_nid2sn(EC_GROUP_get_curve_name(ecgrp))
    /// original /// );

    /// original /// // Here we print the private/public key data in PEM format.
    /// original /// if (!PEM_write_bio_PrivateKey(outbio, pkey, NULL, NULL, 0, 0, NULL))
    /// original ///     BIO_printf(outbio, "Error writing private key data in PEM format");

    /// original /// if (!PEM_write_bio_PUBKEY(outbio, pkey))
    /// original ///     BIO_printf(outbio, "Error writing public key data in PEM format");
    //====================================================================//
    // public key
    //Pass the EVP_PKEY to EVP_PKEY_get1_EC_KEY() to get an EC_KEY.
    //Pass the EC_KEY to EC_KEY_get0_public_key() to get an EC_POINT.
    //Pass the EC_POINT to EC_POINT_point2oct() to get octets, which are just unsigned char *.
    //====================================================================//
    const EC_POINT * ecp = EC_KEY_get0_public_key(myecc);
     
    char * brr = EC_POINT_point2hex(ecgrp, ecp, POINT_CONVERSION_COMPRESSED, NULL);

    if (brr)
    {
        for (int i = 0; brr[i] != '\0'; ++i)
        {
            printf("%c", brr[i]);
        }
    }
    else
    {
        printf("ERROR");
    }

    printf("\n");
    fflush(stdout);

    OPENSSL_free(brr);

    //====================================================================//
    // secret key
    //Pass the EVP_PKEY to EVP_PKEY_get1_EC_KEY() to get an EC_KEY.
    //Pass the EC_KEY to EC_KEY_get0_private_key() to get a BIGNUM.
    //Pass the BIGNUM to BN_bn2mpi() to get an mpi, which is a format written to unsigned char *.
    //====================================================================//
    const BIGNUM * bn = EC_KEY_get0_private_key(myecc);
    char * arr = BN_bn2hex(bn);

    if (arr)
    {
        for (int i = 0; arr[i] != '\0'; ++i)
        {
            printf("%c", arr[i]);
        }
    }
    else
    {
        printf("ERROR");
    }

    printf("\n");
    fflush(stdout);

    //====================================================================//
    // Free up all structures
    EVP_PKEY_free(pkey);
    EC_KEY_free(myecc);
    BIO_free_all(outbio);

    exit(0);
}
