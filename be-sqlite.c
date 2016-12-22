/*
 * Copyright (c) 2013 Jan-Piet Mens <jpmens()gmail.com>
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of mosquitto nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifdef BE_SQLITE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "be-sqlite.h"
#include "hash.h"
#include "log.h"

void *be_sqlite_init()
{
	struct sqlite_backend *conf;
	int res;
	int flags = SQLITE_OPEN_READONLY | SQLITE_OPEN_SHAREDCACHE;
	char *dbpath, *userquery, *superquery, *aclquery;

	if ((dbpath = p_stab("dbpath")) == NULL) {
		_fatal("Mandatory parameter `dbpath' missing");
		return (NULL);
	}

	if ((userquery = p_stab("sqliteuserquery")) == NULL) {
		_fatal("Mandatory parameter `sqliteuserquery' missing");
		return (NULL);
	}
	
	if ((superquery = p_stab("sqlitesuperquery")) == NULL) {
                _log(LOG_DEBUG, "Optional parameter `sqlitesuperquery' missing");
        }
	
	if ((aclquery = p_stab("sqliteaclquery")) == NULL) {
                _log(LOG_DEBUG, "Optional parameter `sqliteaclquery' missing");
        }

	conf = (struct sqlite_backend *)malloc(sizeof(struct sqlite_backend));

	if (sqlite3_open_v2(dbpath, &conf->sq, flags, NULL) != SQLITE_OK) {
		perror(dbpath);
		free(conf);
		return (NULL);
	}

	if ((res = sqlite3_prepare_v2(conf->sq, userquery, strlen(userquery), &conf->userquery, NULL)) != SQLITE_OK) {
		fprintf(stderr, "Can't prepare userquery: %s\n", sqlite3_errmsg(conf->sq));
		sqlite3_close(conf->sq);
		free(conf);
		return (NULL);
	}
	
	if (superquery != NULL) {
            if ((res = sqlite3_prepare_v2(conf->sq, superquery, strlen(superquery), &conf->superquery, NULL)) != SQLITE_OK) {
                    fprintf(stderr, "Can't prepare superquery: %s\n", sqlite3_errmsg(conf->sq));
                    sqlite3_close(conf->sq);
                    free(conf);
                    return (NULL);
            }
        }
	
	if (aclquery != NULL) {
            if ((res = sqlite3_prepare_v2(conf->sq, aclquery, strlen(aclquery), &conf->aclquery, NULL)) != SQLITE_OK) {
                    fprintf(stderr, "Can't prepare aclquery: %s\n", sqlite3_errmsg(conf->sq));
                    sqlite3_close(conf->sq);
                    free(conf);
                    return (NULL);
            }
        }
        
	return (conf);
}

void be_sqlite_destroy(void *handle)
{
	struct sqlite_backend *conf = (struct sqlite_backend *)handle;

	if (conf) {
		sqlite3_finalize(conf->userquery);
		sqlite3_close(conf->sq);
		free(conf);
	}
}

char *be_sqlite_getuser(void *handle, const char *username, const char *password, int *authenticated)
{
	struct sqlite_backend *conf = (struct sqlite_backend *)handle;
	int res;
	char *value = NULL, *v;

	if (!conf)
		return (NULL);

	sqlite3_reset(conf->userquery);
	sqlite3_clear_bindings(conf->userquery);

	res = sqlite3_bind_text(conf->userquery, 1, username, -1, SQLITE_STATIC);
	if (res != SQLITE_OK) {
		puts("Can't bind");
		goto out;
	}

	res = sqlite3_step(conf->userquery);
	if (res == SQLITE_ROW) {
		v = (char *)sqlite3_column_text(conf->userquery, 0);
		if (v)
			value = strdup(v);
	} else {
            fprintf(stderr, "Can't query: [%d] %s\n", res, sqlite3_errmsg(conf->sq));
        }

    out:
	sqlite3_reset(conf->userquery);

	return (value);
}

int be_sqlite_superuser(void *handle, const char *username)
{
	struct sqlite_backend *conf = (struct sqlite_backend *)handle;
        int res;
        int sq_username_idx;
        int issuper = FALSE;

        if (!conf || !conf->superquery || !username || !*username)
                return (FALSE);
        
        sqlite3_reset(conf->superquery);
        sqlite3_clear_bindings(conf->superquery);
        
        sq_username_idx = sqlite3_bind_parameter_index(conf->superquery, ":usr");
        if (sq_username_idx != 0) {
                res = sqlite3_bind_text(conf->superquery, sq_username_idx, username, -1, SQLITE_STATIC);
                if (res != SQLITE_OK) {
                        puts("Can't bind");
                        goto out;
                }
        }
        
        res = sqlite3_step(conf->superquery);
        if (res == SQLITE_ROW) {
                issuper = sqlite3_column_int(conf->superquery, 0);
        } else {
            fprintf(stderr, "Can't query: [%d] %s\n", res, sqlite3_errmsg(conf->sq));
        }
        
    out:
        sqlite3_reset(conf->superquery);

        return (issuper);
}

int be_sqlite_aclcheck(void *handle, const char *clientid, const char *username, const char *topic, int acc)
{
        struct sqlite_backend *conf = (struct sqlite_backend *)handle;
        int res;
        int sq_username_idx, sq_acc_idx;
        int match = FALSE;
        char *v;

        if (!conf || !conf->aclquery)
                return (FALSE);

        sqlite3_reset(conf->aclquery);
        sqlite3_clear_bindings(conf->aclquery);
        
        sq_username_idx = sqlite3_bind_parameter_index(conf->aclquery, ":usr");
        if (sq_username_idx != 0) {
                res = sqlite3_bind_text(conf->aclquery, sq_username_idx, username, -1, SQLITE_STATIC);
                if (res != SQLITE_OK) {
                        puts("Can't bind");
                        goto out;
                }
        }
        sq_acc_idx = sqlite3_bind_parameter_index(conf->aclquery, ":acc");
        if (sq_acc_idx != 0) {
                res = sqlite3_bind_int(conf->aclquery, sq_acc_idx, acc);
                if (res != SQLITE_OK) {
                        puts("Can't bind");
                        goto out;
                }
        }
        
        while ((res = sqlite3_step(conf->aclquery)) == SQLITE_ROW) {
                v = (char *)sqlite3_column_text(conf->aclquery, 0);
                if (v != NULL) {
                        /* Check mosquitto_match_topic.
                         * If true, set match and break out of loop. */
                        
                        char *expanded;
                        
                        t_expand(clientid, username, v, &expanded);
                        if (expanded && *expanded) {
                                mosquitto_topic_matches_sub(expanded, topic, &bf);
                                match |= bf;
                                _log(LOG_DEBUG, "  sqlite: topic_matches(%s, %s) == %d",
                                        expanded, v, bf);

                                free(expanded);
                        }
                        if ( match != 0 ) {
                                goto out;
                        }
                }
        }
        if (res != SQLITE_DONE) {
            fprintf(stderr, "Can't query: [%d] %s\n", res, sqlite3_errmsg(conf->sq));
        }
        
    out:
        sqlite3_reset(conf->aclquery);

        return (match);
}
#endif /* BE_SQLITE */
