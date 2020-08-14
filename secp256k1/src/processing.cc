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
#include <sys/types.h>
#include <fstream>
#include <string>

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
    char * pool,
    int * keep
)
{
    std::ifstream file(
        fileName, std::ios::in | std::ios::binary | std::ios::ate
    );

    if (!file.is_open())
    {
        LOG(ERROR) << "Failure during opening configuration file";
        return EXIT_FAILURE;
    }

    file.seekg(0, std::ios::end);
    long int len = file.tellg();
    json_t config(len + 1, CONF_LEN);

    file.seekg(0, std::ios::beg);
    file.read(config.ptr, len);
    file.close();
    
    // need to null terminate config string, at least for win32
    config.ptr[len] = '\0';

    jsmn_parser parser;
    jsmn_init(&parser);

    VLOG(1) << "config string " << config.ptr;
    
    int numtoks = jsmn_parse(
        &parser, config.ptr, strlen(config.ptr), config.toks, CONF_LEN
    );

    if (numtoks < 0)
    {
        LOG(ERROR) << "Jsmn failed to recognise configuration option";
        return EXIT_FAILURE;
    }
    
    uint8_t readNode = 0;
    uint8_t readSeed = 0;
    uint8_t readSeedPass = 0;

    // default keepPrehash = false
    *keep = 0;

    char* seedstring;
    char* seedPass;

    for (int t = 1; t < numtoks; t += 2)
    {
        if (config.jsoneq(t, "node"))
        {
            from[0] = '\0';
            to[0] = '\0';
            pool[0] = '\0';
            strncat(
                from, config.GetTokenStart(t + 1), config.GetTokenLen(t + 1)
            );

            strcat(from, "/mining/candidate");
            
            strncat(to, config.GetTokenStart(t + 1), config.GetTokenLen(t + 1));
            strcat(to, "/mining/solution");
            
            strncat(pool, config.GetTokenStart(t + 1), config.GetTokenLen(t + 1));
            strcat(pool, "/mining/share");
            


            VLOG(1) << "from url " << from  << " to url " << to;

            readNode = 1;
        }
        else if (config.jsoneq(t, "keepPrehash"))
        {
            if (!strncmp(config.GetTokenStart(t + 1), "true", 4))
            {
                *keep = 1;

                VLOG(1) << "Setting keepPrehash to 1";
            }
        }
        else if (config.jsoneq(t, "mnemonic") || config.jsoneq(t,"seed"))
        {

            seedstring = (char*)malloc((config.GetTokenLen(t + 1) + 1)*sizeof(char));
            seedstring[0] = '\0';
            strncat(seedstring, config.GetTokenStart(t + 1), config.GetTokenLen(t + 1));
            VLOG(1) << "Mnemonic read: " << seedstring;
            readSeed = 1;
        }
        else if (config.jsoneq(t, "mnemonicPass") || config.jsoneq(t,"seedPass"))
        {

            seedPass = (char*)malloc((config.GetTokenLen(t + 1) + 1)*sizeof(char));
            seedPass[0] = '\0';
            strncat(seedPass, config.GetTokenStart(t + 1), config.GetTokenLen(t + 1));

            readSeedPass = 1;
        }
        else
        {
            LOG(INFO) << "Unrecognized config option, currently valid options are "
                         "\"node\", \"mnemonic\", \"mnemonicPass\" and \"keepPrehash\"";
        }
    }

    if(readSeed && readSeedPass)
    {
        GenerateSecKeyNew(
            seedstring, strlen(seedstring), sk,
            skstr, seedPass
        );
        free(seedstring);
        free(seedPass);
    }
    else if( readSeed && !readSeedPass)
    {
        GenerateSecKeyNew(
            seedstring, strlen(seedstring), sk,
            skstr, ""
        );
        free(seedstring);
    }

    #ifdef EMBEDDED_MNEMONIC
        #ifdef EMBEDDED_PASS
         GenerateSecKeyNew(
            EMBEDDED_MNEMONIC, strlen(EMBEDDED_MNEMONIC), sk,
            skstr, EMBEDDED_PASS
        );
        readSeedPass = 1;
        readSeed = 1;
        #else
        GenerateSecKeyNew(
            EMBEDDED_MNEMONIC, strlen(EMBEDDED_MNEMONIC), sk,
            skstr, ""
        );
        readSeed = 1;
        #endif
    #else

    #endif





    if (readSeed & readNode) { return EXIT_SUCCESS; }
    else
    {
        LOG(ERROR) << "Incomplete config: node or seed are not specified";
        return EXIT_FAILURE;
    }
}

////////////////////////////////////////////////////////////////////////////////
//  Print public key
////////////////////////////////////////////////////////////////////////////////
int PrintPublicKey(const char * pkstr, char * str)
{
    sprintf(
        str, "   pkHex = %.2s%.16s%.16s%.16s%.16s",
        pkstr, pkstr + 2, pkstr + 18, pkstr + 34, pkstr + 50
    );

    return EXIT_SUCCESS;
}

int PrintPublicKey(const uint8_t * pk, char * str)
{
    sprintf(
        str, "   pkHex = 0x%02X%016lX%016lX%016lX%016lX",
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
