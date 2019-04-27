// processing.cc

/*******************************************************************************

    PROCESSING -- Puzzle cycle execution support

*******************************************************************************/
#include "../include/easylogging++.h"
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
#include <string>

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
// understands single-level json strings ({"a":"b", "c":"d", ...})
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
    VLOG(1) << "Config file length " << len;
    
    json_t config(len+1, CONF_LEN);
    fgets(config.ptr, len+1, in);
    //fread(config.ptr, sizeof(char), len, in);
    //config.ptr[len] = '\0';

    fclose(in);
    
    jsmn_parser parser;
    jsmn_init(&parser);

    VLOG(1) << "config string " << config.ptr;
    
    int numtoks = jsmn_parse(
        &parser, config.ptr, strlen(config.ptr), config.toks, CONF_LEN
    );

    if (numtoks < 0)
    {
        LOG(ERROR) << numtoks << " jsmn config parsing error";
        return EXIT_FAILURE;
    }
    
    int readNode = 0;
    int readSeed = 0;

    for (int i = 1; i < numtoks; ++i)
    {
        if (!(config.jsoneq(i, "node")))
        {
            from[0] = '\0';
            to[0] = '\0';

            strncat(
                from, config.GetTokenStart(i + 1), config.GetTokenLen(i + 1)
            );
            strcat(from, "/mining/candidate");
            
            strncat(to, config.GetTokenStart(i + 1), config.GetTokenLen(i + 1));
            strcat(to, "/mining/solution");

            VLOG(1) << "from url " << from  << " to url " << to;

            readNode = 1;
            ++i;
        }
        else if (!(config.jsoneq(i,"keepPrehash")))
        {
            if (!strncmp(config.GetTokenStart(i + 1), "true", 4))
            {
                *keep = 1;

                VLOG(1) << "Setting keepPrehash to 1";
            }
            else { *keep = 0; }

            ++i;
        }
        else if (!(config.jsoneq(i, "seed")))
        {
            // maybe need to make it little bit prettier,
            // without changing string itself
            --(config.toks[i + 1].start);
            *(config.GetTokenStart(i + 1)) = '1';

            GenerateSecKey(
                config.GetTokenStart(i + 1), config.GetTokenLen(i + 1), sk,
                skstr
            );

            readSeed = 1;
            ++i;
        }
    }
    
    if (readSeed & readNode) { return EXIT_SUCCESS; }
    else
    {
        LOG(ERROR) << "Node or seed were not specified, bad config";
        return EXIT_FAILURE;
    }
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
