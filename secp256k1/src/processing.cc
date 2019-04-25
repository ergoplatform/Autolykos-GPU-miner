// processing.cc

/*******************************************************************************

    PROCESSING -- Puzzle cycle execution support

*******************************************************************************/

#include "../include/conversion.h"
#include "../include/cryptography.h"
#include "../include/definitions.h"
#include "../include/jsmn.h"
#include <ctype.h>
#include <curl/curl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

////////////////////////////////////////////////////////////////////////////////
//  Find file size
////////////////////////////////////////////////////////////////////////////////
long int FindFileSize(const char * fileName)
{
    struct stat st;

    CALL_STATUS(stat(fileName, &st), ERROR_STAT, 0);

    return st.st_size;
}

////////////////////////////////////////////////////////////////////////////////
//  Read config file
////////////////////////////////////////////////////////////////////////////////
int ReadConfig(
    const char * fileName,
    uint8_t * sk,
    char * skstr,
    char * from,
    char * to,
    int * keep
)
{
    FILE * in = fopen(fileName, "r");

    long int len = FindFileSize(fileName); 
    json_t config(len, CONF_LEN);

    for (int i = 0; (config.ptr[i] = fgetc(in)) != EOF; ++i) {}

    fclose(in);

    jsmn_parser parser;
    jsmn_init(&parser);

    jsmn_parse(&parser, config.ptr, config.len, config.toks, CONF_LEN);

    for (
        int i = config.GetTokenStartPos(KEEP_POS);
        i < config.GetTokenEndPos(KEEP_POS);
        ++i
    ) { config.ptr[i] = toupper(config.ptr[i]); }

    --(config.toks[SEED_POS].start);
    *(config.GetTokenStart(SEED_POS)) = '1';
    *(config.GetTokenEnd(SEED_POS)) = '\0';
    *(config.GetTokenEnd(NODE_POS)) = '\0';
    *(config.GetTokenEnd(KEEP_POS)) = '\0';

    if (!strncmp(
        config.GetTokenStart(KEEP_POS), "TRUE", config.GetTokenLen(KEEP_POS)
    ))
    {
        *keep = 1;
    }
    else if (strncmp(
        config.GetTokenStart(KEEP_POS), "FALSE", config.GetTokenLen(KEEP_POS)
    ))
    {
        fprintf(stderr, "ABORT:  Wrong value \"keepPrehash\"\n");

        fprintf(
            stderr, "Miner is now terminated\n"
            "========================================"
            "========================================\n"
        );

        return EXIT_FAILURE;
    }

    GenerateSecKey(
        config.GetTokenStart(SEED_POS), config.GetTokenLen(SEED_POS), sk, skstr
    );

    strcpy(from, config.GetTokenStart(NODE_POS));
    strcpy(from + config.GetTokenLen(NODE_POS), "/mining/candidate");

    strcpy(to, config.GetTokenStart(NODE_POS));
    strcpy(to + config.GetTokenLen(NODE_POS), "/mining/solution");

    return EXIT_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////
//  Print public key
////////////////////////////////////////////////////////////////////////////////
int PrintPublicKey(const char * pkstr, char * str)
{
    sprintf(
        str, "   pk = 0x%.2s %.16s %.16s %.16s %.16s",
        pkstr, pkstr + 2, pkstr + 18, pkstr + 34, pkstr + 50
    );

    return EXIT_SUCCESS;
}

int PrintPublicKey(const uint8_t * pk, char * str)
{
    sprintf(
        str, "   pk = 0x%02lX %016lX %016lX %016lX %016lX",
        pk[0],
        REVERSE_ENDIAN((uint64_t *)(pk + 1) + 0),
        REVERSE_ENDIAN((uint64_t *)(pk + 1) + 1),
        REVERSE_ENDIAN((uint64_t *)(pk + 1) + 2),
        REVERSE_ENDIAN((uint64_t *)(pk + 1) + 3)
    );

    return EXIT_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////
//  Print Autolukos puzzle solution
////////////////////////////////////////////////////////////////////////////////
int PrintPuzzleSolution(
    const uint8_t * nonce,
    const uint8_t * sol,
    char * str
)
{
    sprintf(
        str, "   nonce = 0x%016lX\n"
        "       d = 0x%016lX %016lX %016lX %016lX",
        *((uint64_t *)nonce),
        ((uint64_t *)sol)[3], ((uint64_t *)sol)[2],
        ((uint64_t *)sol)[1], ((uint64_t *)sol)[0]
    );

    return EXIT_SUCCESS;
}

// processing.cc
