/* v3_rus.c */
/*
 * Written by Dmitry Belyavskiy for the OpenSSL project
 * 2015.
 */
/* ====================================================================
 * Copyright (c) 1999-2004 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

#include <stdio.h>
#include <string.h>
#include <openssl/asn1t.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

static char *i2s_ASN1_UTF8STRING(const X509V3_EXT_METHOD *method,
                                ASN1_UTF8STRING *utf8str)
{
    char *tmp;
    if (!utf8str || !utf8str->length)
        return NULL;
    if (!(tmp = OPENSSL_malloc(utf8str->length + 1))) {
        X509V3err(X509V3_F_I2S_ASN1_UTF8STRING, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    memcpy(tmp, utf8str->data, utf8str->length);
    tmp[utf8str->length] = 0;
    return tmp;
}

static ASN1_UTF8STRING *s2i_ASN1_UTF8STRING(X509V3_EXT_METHOD *method,
                                          X509V3_CTX *ctx, char *str)
{
    ASN1_UTF8STRING *utf8str;
    if (!str) {
        X509V3err(X509V3_F_S2I_ASN1_UTF8STRING,
                  X509V3_R_INVALID_NULL_ARGUMENT);
        return NULL;
    }
    if (!(utf8str = ASN1_STRING_type_new(V_ASN1_UTF8STRING)))
        goto err;
    if (!ASN1_STRING_set((ASN1_STRING *)utf8str, (unsigned char *)str,
                         strlen(str))) {
        ASN1_STRING_free(utf8str);
        goto err;
    }
#ifdef CHARSET_EBCDIC
    ebcdic2ascii(utf8str->data, utf8str->data, utf8str->length);
#endif                          /* CHARSET_EBCDIC */
    return utf8str;
 err:
    X509V3err(X509V3_F_S2I_ASN1_UTF8STRING, ERR_R_MALLOC_FAILURE);
    return NULL;
}

const X509V3_EXT_METHOD v3_subject_sign_tool = {
    NID_subjectSignTool, 0, ASN1_ITEM_ref(ASN1_UTF8STRING),
    0, 0, 0, 0,
    (X509V3_EXT_I2S)i2s_ASN1_UTF8STRING,
    (X509V3_EXT_S2I)s2i_ASN1_UTF8STRING,
    0, 0, 0, 0, NULL
};

typedef struct ISSUER_SIGN_TOOL_st {
    ASN1_UTF8STRING *signTool;
    ASN1_UTF8STRING *cATool;
    ASN1_UTF8STRING *signToolCert;
    ASN1_UTF8STRING *cAToolCert;
} ISSUER_SIGN_TOOL;

ASN1_SEQUENCE(ISSUER_SIGN_TOOL) = {
        ASN1_SIMPLE(ISSUER_SIGN_TOOL, signTool, ASN1_UTF8STRING),
        ASN1_SIMPLE(ISSUER_SIGN_TOOL, cATool, ASN1_UTF8STRING),
        ASN1_SIMPLE(ISSUER_SIGN_TOOL, signToolCert, ASN1_UTF8STRING),
        ASN1_SIMPLE(ISSUER_SIGN_TOOL, cAToolCert, ASN1_UTF8STRING)
} ASN1_SEQUENCE_END(ISSUER_SIGN_TOOL)

IMPLEMENT_ASN1_FUNCTIONS(ISSUER_SIGN_TOOL)

static int i2r_ISSUER_SIGN_TOOL(X509V3_EXT_METHOD *method,
                                 ISSUER_SIGN_TOOL *ist, BIO *out,
                                 int indent)
{
    if (ist->signTool) {
    		BIO_printf(out, "%*s", indent, "");
        BIO_write(out, "signTool:     ", 14);
				BIO_write(out, ist->signTool->data, ist->signTool->length);
				BIO_write(out, "\n", 1);
    }
    if (ist->cATool) {
    		BIO_printf(out, "%*s", indent, "");
        BIO_write(out, "cATool:       ", 14);
				BIO_write(out, ist->cATool->data, ist->cATool->length);
				BIO_write(out, "\n", 1);
    }
    if (ist->signToolCert) {
    		BIO_printf(out, "%*s", indent, "");
        BIO_write(out, "signToolCert: ", 14);
				BIO_write(out, ist->signToolCert->data, ist->signToolCert->length);
				BIO_write(out, "\n", 1);
    }
    if (ist->cAToolCert) {
    		BIO_printf(out, "%*s", indent, "");
        BIO_write(out, "cAToolCert:   ", 14);
				BIO_write(out, ist->cAToolCert->data, ist->cAToolCert->length);
				BIO_write(out, "\n", 1);
    }
    return 1;
}

const X509V3_EXT_METHOD v3_issuer_sign_tool = {
    NID_issuerSignTool, X509V3_EXT_MULTILINE, ASN1_ITEM_ref(ISSUER_SIGN_TOOL),
    0, 0, 0, 0,
		0, 0,
    0, /*(X509V3_EXT_I2V)i2v_ISSUER_SIGN_TOOL,*/
    0,
    (X509V3_EXT_I2R)i2r_ISSUER_SIGN_TOOL, 0, NULL
};
