
/**
 * @file   ngx_http_limit_req_freq_module.c
 * @author Kryštof Šimon <simonkry@fit.cvut.cz>
 * @date   2025-05-14 21:05:50
 *
 * @brief  nginx module for request frequency limiting
 *         via the sliding window counter algorithm.
 *
 * @credits
 * ngx_http_limit_req_module by nginx
 * @see  https://github.com/nginx/nginx/blob/release-1.26.3/src/http/modules/ngx_http_limit_req_module.c
 */


/*
 * Copyright (C) 2002-2021 Igor Sysoev
 * Copyright (C) 2011-2024 Nginx, Inc.
 * Copyright (C) 2025 Kryštof Šimon
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#define NGX_HTTP_LIMIT_REQ_PASSED                1
#define NGX_HTTP_LIMIT_REQ_REJECTED              2
#define NGX_HTTP_LIMIT_REQ_REJECTED_DRY_RUN      3
#define NGX_EXPIRE_TIME                      60000  /* 60 seconds */


typedef struct {
    u_char                            color;     /* 1 byte */
    u_char                            dummy;     /* 1 byte */
    u_short                           len;       /* 2 bytes */
    ngx_msec_t                        boundary;  /* 4/8 bytes */
    ngx_uint_t                        previous;  /* 4/8 bytes */
    ngx_uint_t                        current;   /* 4/8 bytes */
    ngx_uint_t                        count;     /* 4/8 bytes */
    ngx_queue_t                       queue;     /* 8/16 bytes */
    u_char                            data[1];   /* variable-length key */
} ngx_http_limit_req_freq_node_t;


typedef struct {
    ngx_rbtree_t                      rbtree;
    ngx_rbtree_node_t                 sentinel;
    ngx_queue_t                       queue;
} ngx_http_limit_req_freq_shctx_t;


typedef struct {
    ngx_http_limit_req_freq_shctx_t  *sh;
    ngx_slab_pool_t                  *shpool;
    ngx_msec_t                        window;
    /* integer value, 1000 corresponds to 1.000 requests per rolling window */
    ngx_uint_t                        max_rate;
    ngx_http_complex_value_t          key;  /* e.g. client IP */
    ngx_http_limit_req_freq_node_t   *node;
} ngx_http_limit_req_freq_ctx_t;


typedef struct {
    ngx_shm_zone_t                   *shm_zone;
    ngx_flag_t                        count_rejects;
} ngx_http_limit_req_freq_limit_t;


typedef struct {
    ngx_array_t                       limits;
    ngx_uint_t                        limit_log_level;
    ngx_uint_t                        status_code;
    ngx_flag_t                        dry_run;
} ngx_http_limit_req_freq_conf_t;


static ngx_int_t ngx_http_limit_req_freq_lookup(ngx_http_limit_req_freq_limit_t *limit,
    ngx_uint_t hash, ngx_str_t *key, ngx_uint_t account);
static void ngx_http_limit_req_freq_unlock(ngx_http_limit_req_freq_limit_t *limits,
    ngx_uint_t n);
static void ngx_http_limit_req_freq_expire(ngx_http_limit_req_freq_ctx_t *ctx,
    ngx_uint_t n);

static ngx_int_t ngx_http_limit_req_freq_status_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static void *ngx_http_limit_req_freq_create_conf(ngx_conf_t *cf);
static char *ngx_http_limit_req_freq_merge_conf(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_http_limit_req_freq_zone(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_limit_req_freq(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static ngx_int_t ngx_http_limit_req_freq_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_http_limit_req_freq_init(ngx_conf_t *cf);


static ngx_conf_enum_t  ngx_http_limit_req_freq_log_levels[] = {
    { ngx_string("info"), NGX_LOG_INFO },
    { ngx_string("notice"), NGX_LOG_NOTICE },
    { ngx_string("warn"), NGX_LOG_WARN },
    { ngx_string("error"), NGX_LOG_ERR },
    { ngx_null_string, 0 }
};


static ngx_conf_num_bounds_t  ngx_http_limit_req_freq_status_bounds = {
    ngx_conf_check_num_bounds, 400, 599
};


static ngx_command_t  ngx_http_limit_req_freq_commands[] = {

    { ngx_string("limit_req_freq_zone"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE2|NGX_CONF_TAKE3|NGX_CONF_TAKE4,
      ngx_http_limit_req_freq_zone,
      0,
      0,
      NULL },

    { ngx_string("limit_req_freq"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE12,
      ngx_http_limit_req_freq,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("limit_req_freq_log_level"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_limit_req_freq_conf_t, limit_log_level),
      &ngx_http_limit_req_freq_log_levels },

    { ngx_string("limit_req_freq_status"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_limit_req_freq_conf_t, status_code),
      &ngx_http_limit_req_freq_status_bounds },

    { ngx_string("limit_req_freq_dry_run"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_limit_req_freq_conf_t, dry_run),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_limit_req_freq_module_ctx = {
    ngx_http_limit_req_freq_add_variables,  /* preconfiguration */
    ngx_http_limit_req_freq_init,  /* postconfiguration */

    NULL,  /* create main configuration */
    NULL,  /* init main configuration */

    NULL,  /* create server configuration */
    NULL,  /* merge server configuration */

    ngx_http_limit_req_freq_create_conf,  /* create location configuration */
    ngx_http_limit_req_freq_merge_conf  /* merge location configuration */
};


ngx_module_t  ngx_http_limit_req_freq_module = {
    NGX_MODULE_V1,
    &ngx_http_limit_req_freq_module_ctx,  /* module context */
    ngx_http_limit_req_freq_commands,  /* module directives */
    NGX_HTTP_MODULE,  /* module type */
    NULL,  /* init master */
    NULL,  /* init module */
    NULL,  /* init process */
    NULL,  /* init thread */
    NULL,  /* exit thread */
    NULL,  /* exit process */
    NULL,  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_variable_t  ngx_http_limit_req_freq_vars[] = {

    { ngx_string("limit_req_freq_status"), NULL,
      ngx_http_limit_req_freq_status_variable, 0, NGX_HTTP_VAR_NOCACHEABLE, 0 },

      ngx_http_null_variable
};


static ngx_str_t  ngx_http_limit_req_freq_status[] = {
    ngx_string("PASSED"),
    ngx_string("DELAYED"),
    ngx_string("REJECTED"),
    ngx_string("DELAYED_DRY_RUN"),
    ngx_string("REJECTED_DRY_RUN")
};


static ngx_int_t
ngx_http_limit_req_freq_handler(ngx_http_request_t *r)
{
    uint32_t                          hash;
    ngx_str_t                         key;
    ngx_int_t                         rc;
    ngx_uint_t                        n;
    ngx_http_limit_req_freq_ctx_t    *ctx;
    ngx_http_limit_req_freq_conf_t   *lrcf;
    ngx_http_limit_req_freq_limit_t  *limit, *limits;

    if (r->main->limit_req_status) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "limit request freq handler: status already set");
        return NGX_DECLINED;
    }

    lrcf = ngx_http_get_module_loc_conf(r, ngx_http_limit_req_freq_module);
    limits = lrcf->limits.elts;

    rc = NGX_DECLINED;

#if (NGX_SUPPRESS_WARN)
    limit = NULL;
#endif

    for (n = 0; n < lrcf->limits.nelts; n++) {

        limit = &limits[n];

        ctx = limit->shm_zone->data;

        if (ngx_http_complex_value(r, &ctx->key, &key) != NGX_OK) {
            ngx_http_limit_req_freq_unlock(limits, n);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        if (key.len == 0) {
            continue;
        }

        if (key.len > 65535) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "the value of the \"%V\" key "
                          "is more than 65535 bytes: \"%V\"",
                          &ctx->key.value, &key);
            continue;
        }

        hash = ngx_crc32_short(key.data, key.len);

        ngx_shmtx_lock(&ctx->shpool->mutex);

        rc = ngx_http_limit_req_freq_lookup(limit, hash, &key,
                                            (n == lrcf->limits.nelts - 1));

        ngx_shmtx_unlock(&ctx->shpool->mutex);

        if (rc != NGX_AGAIN) {
            break;
        }
    }

    if (rc == NGX_DECLINED) {
        return NGX_DECLINED;
    }

    ngx_http_limit_req_freq_unlock(limits, n);

    if (rc == NGX_BUSY || rc == NGX_ERROR) {

        if (lrcf->dry_run) {
            r->main->limit_req_status = NGX_HTTP_LIMIT_REQ_REJECTED_DRY_RUN;
            return NGX_DECLINED;
        }

        r->main->limit_req_status = NGX_HTTP_LIMIT_REQ_REJECTED;

        return lrcf->status_code;
    }

    /* rc == NGX_AGAIN || rc == NGX_OK */

    if (rc == NGX_OK) {
        r->main->limit_req_status = NGX_HTTP_LIMIT_REQ_PASSED;
        return NGX_DECLINED;
    }

    return NGX_AGAIN;
}


static void
ngx_http_limit_req_freq_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t          **p;
    ngx_http_limit_req_freq_node_t   *lrn, *lrnt;

    for ( ;; ) {

        if (node->key < temp->key) {

            p = &temp->left;

        } else if (node->key > temp->key) {

            p = &temp->right;

        } else { /* node->key == temp->key */

            lrn = (ngx_http_limit_req_freq_node_t *) &node->color;
            lrnt = (ngx_http_limit_req_freq_node_t *) &temp->color;

            p = (ngx_memn2cmp(lrn->data, lrnt->data, lrn->len, lrnt->len) < 0)
                ? &temp->left : &temp->right;
        }

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);
}


static ngx_int_t
ngx_http_limit_req_freq_lookup(ngx_http_limit_req_freq_limit_t *limit,
    ngx_uint_t hash, ngx_str_t *key, ngx_uint_t account)
{
    size_t                           size;
    ngx_int_t                        rc;
    ngx_uint_t                       rate;
    ngx_msec_t                       now, ms;
    ngx_rbtree_node_t               *node, *sentinel;
    ngx_http_limit_req_freq_ctx_t   *ctx;
    ngx_http_limit_req_freq_node_t  *lr;

    ctx = limit->shm_zone->data;

    /* cleanup of 0 to 2 stale entries */

    ngx_http_limit_req_freq_expire(ctx, 1);

    node = ctx->sh->rbtree.root;
    sentinel = ctx->sh->rbtree.sentinel;

    while (node != sentinel) {

        if (hash < node->key) {
            node = node->left;
            continue;
        }

        if (hash > node->key) {
            node = node->right;
            continue;
        }

        /* hash == node->key */

        lr = (ngx_http_limit_req_freq_node_t *) &node->color;

        rc = ngx_memn2cmp(key->data, lr->data, key->len, (size_t) lr->len);

        if (rc == 0) {

            /* entry found, move to the front of the LRU queue */

            ngx_queue_remove(&lr->queue);
            ngx_queue_insert_head(&ctx->sh->queue, &lr->queue);

            ngx_time_update();
            now = ngx_current_msec;

            if (now < lr->boundary) {

                /* safeguard against potential time wraparound */

                ngx_log_debug0(NGX_LOG_DEBUG_HTTP, limit->shm_zone->shm.log, 0,
                               "limit request freq lookup: time wraparound");

                ms = UINT_MAX - lr->boundary + now + 1;

            } else {
                ms = now - lr->boundary;
            }

            if (ms >= ctx->window) {

                /* window rotation */

                if (ms >= 2 * ctx->window) {
                    lr->previous = 0;

                } else {
                    lr->previous = lr->current;
                }

                lr->current = 0;
                lr->boundary += (ms / ctx->window) * ctx->window;
                ms %= ctx->window;
            }

            /* weighted approximation with precision x1000 */

            rate = (1000 * lr->current) + 1000 +
                   (1000 * lr->previous * (ctx->window - ms) / ctx->window);

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, limit->shm_zone->shm.log, 0,
                           "limit request freq lookup: rate=%ui, time=%ui",
                           rate, now);

            if (rate > ctx->max_rate) {
                if (limit->count_rejects) {
                    lr->current++;
                }
                return NGX_BUSY;
            }

            lr->current++;

            if (account) {
                return NGX_OK;
            }

            lr->count++;

            ctx->node = lr;

            return NGX_AGAIN;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    size = offsetof(ngx_rbtree_node_t, color)
           + offsetof(ngx_http_limit_req_freq_node_t, data)
           + key->len;

    node = ngx_slab_alloc_locked(ctx->shpool, size);

    if (node == NULL) {
        ngx_http_limit_req_freq_expire(ctx, 0);

        node = ngx_slab_alloc_locked(ctx->shpool, size);
        if (node == NULL) {
            ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0,
                          "could not allocate node%s", ctx->shpool->log_ctx);
            return NGX_ERROR;
        }
    }

    node->key = hash;

    lr = (ngx_http_limit_req_freq_node_t *) &node->color;

    ngx_time_update();
    lr->boundary = ngx_current_msec;
    lr->len = (u_short) key->len;
    lr->previous = 0;
    lr->current = 1;

    ngx_memcpy(lr->data, key->data, key->len);

    ngx_rbtree_insert(&ctx->sh->rbtree, node);

    ngx_queue_insert_head(&ctx->sh->queue, &lr->queue);

    if (account) {
        lr->count = 0;
        return NGX_OK;
    }

    lr->count = 1;

    ctx->node = lr;

    return NGX_AGAIN;
}


static void
ngx_http_limit_req_freq_unlock(ngx_http_limit_req_freq_limit_t *limits, ngx_uint_t n)
{
    ngx_http_limit_req_freq_ctx_t  *ctx;

    while (n--) {
        ctx = limits[n].shm_zone->data;

        if (ctx->node == NULL) {
            continue;
        }

        ngx_shmtx_lock(&ctx->shpool->mutex);

        ctx->node->count--;

        ngx_shmtx_unlock(&ctx->shpool->mutex);

        ctx->node = NULL;
    }
}


static void
ngx_http_limit_req_freq_expire(ngx_http_limit_req_freq_ctx_t *ctx, ngx_uint_t n)
{
    ngx_msec_t                       now, ms;
    ngx_queue_t                     *q;
    ngx_rbtree_node_t               *node;
    ngx_http_limit_req_freq_node_t  *lr;

    if (ngx_queue_empty(&ctx->sh->queue)) {
        return;
    }

    /*
     * n == 1 deletes one or two zero counter entries
     * n == 0 deletes oldest entry by force
     *        and one or two zero counter entries
     */

    while (n < 3) {

        q = ngx_queue_last(&ctx->sh->queue);

        lr = ngx_queue_data(q, ngx_http_limit_req_freq_node_t, queue);

        if (lr->count) {

            /*
             * There is not much sense in looking further,
             * because we bump nodes on the lookup stage.
             */

            return;
        }

        if (n++ != 0) {

            ngx_time_update();
            now = ngx_current_msec;

            if (now < lr->boundary) {

                /* safeguard against potential time wraparound */

                ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                               "limit request freq expire: time wraparound");

                ms = UINT_MAX - lr->boundary + now + 1;

            } else {
                ms = now - lr->boundary;
            }

            if (ms < NGX_EXPIRE_TIME) {
                return;
            }

            if (ms >= ctx->window) {

                /* window rotation */

                if (ms >= 2 * ctx->window) {
                    lr->previous = 0;

                } else {
                    lr->previous = lr->current;
                }

                lr->current = 0;
                lr->boundary += (ms / ctx->window) * ctx->window;
            }

            if (lr->previous || lr->current) {

                /* not deleting node since there were recent requests */

                return;
            }
        }

        ngx_queue_remove(q);

        node = (ngx_rbtree_node_t *)
                   ((u_char *) lr - offsetof(ngx_rbtree_node_t, color));

        ngx_rbtree_delete(&ctx->sh->rbtree, node);

        ngx_slab_free_locked(ctx->shpool, node);

        if (ngx_queue_empty(&ctx->sh->queue)) {
            return;
        }
    }
}


static ngx_int_t
ngx_http_limit_req_freq_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    size_t                          len;
    ngx_http_limit_req_freq_ctx_t  *octx = data;
    ngx_http_limit_req_freq_ctx_t  *ctx;

    ctx = shm_zone->data;

    if (octx) {
        if (ctx->key.value.len != octx->key.value.len
            || ngx_strncmp(ctx->key.value.data, octx->key.value.data,
                           ctx->key.value.len)
               != 0)
        {
            ngx_log_error(NGX_LOG_EMERG, shm_zone->shm.log, 0,
                          "limit_req_freq \"%V\" uses the \"%V\" key "
                          "while previously it used the \"%V\" key",
                          &shm_zone->shm.name, &ctx->key.value,
                          &octx->key.value);
            return NGX_ERROR;
        }

        ctx->sh = octx->sh;
        ctx->shpool = octx->shpool;

        return NGX_OK;
    }

    ctx->shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    if (shm_zone->shm.exists) {
        ctx->sh = ctx->shpool->data;

        return NGX_OK;
    }

    ctx->sh = ngx_slab_alloc(ctx->shpool, sizeof(ngx_http_limit_req_freq_shctx_t));
    if (ctx->sh == NULL) {
        return NGX_ERROR;
    }

    ctx->shpool->data = ctx->sh;

    ngx_rbtree_init(&ctx->sh->rbtree, &ctx->sh->sentinel,
                    ngx_http_limit_req_freq_rbtree_insert_value);

    ngx_queue_init(&ctx->sh->queue);

    len = sizeof(" in limit_req_freq zone \"\"") + shm_zone->shm.name.len;

    ctx->shpool->log_ctx = ngx_slab_alloc(ctx->shpool, len);
    if (ctx->shpool->log_ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_sprintf(ctx->shpool->log_ctx, " in limit_req_freq zone \"%V\"%Z",
                &shm_zone->shm.name);

    ctx->shpool->log_nomem = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_limit_req_freq_status_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    if (r->main->limit_req_status == 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->len = ngx_http_limit_req_freq_status[r->main->limit_req_status - 1].len;
    v->data = ngx_http_limit_req_freq_status[r->main->limit_req_status - 1].data;

    return NGX_OK;
}


static void *
ngx_http_limit_req_freq_create_conf(ngx_conf_t *cf)
{
    ngx_http_limit_req_freq_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_limit_req_freq_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->limits.elts = NULL;
     */

    conf->limit_log_level = NGX_CONF_UNSET_UINT;
    conf->status_code = NGX_CONF_UNSET_UINT;
    conf->dry_run = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_http_limit_req_freq_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_limit_req_freq_conf_t *prev = parent;
    ngx_http_limit_req_freq_conf_t *conf = child;

    if (conf->limits.elts == NULL) {
        conf->limits = prev->limits;
    }

    ngx_conf_merge_uint_value(conf->limit_log_level, prev->limit_log_level,
                              NGX_LOG_ERR);

    ngx_conf_merge_uint_value(conf->status_code, prev->status_code,
                              NGX_HTTP_TOO_MANY_REQUESTS);

    ngx_conf_merge_value(conf->dry_run, prev->dry_run, 0);

    return NGX_CONF_OK;
}


static char *
ngx_http_limit_req_freq_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    u_char                            *p;
    size_t                             len;
    ssize_t                            size;
    ngx_str_t                         *value, name, s;
    ngx_int_t                          rate;
    ngx_uint_t                         i, scale_window;
    ngx_msec_int_t                     window;
    ngx_shm_zone_t                    *shm_zone;
    ngx_http_limit_req_freq_ctx_t     *ctx;
    ngx_http_compile_complex_value_t   ccv;

    value = cf->args->elts;

    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_http_limit_req_freq_ctx_t));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &ctx->key;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    size = 0;
    rate = 1; /* requests per window (default value = 1) */
    window = 1000; /* milliseconds (default value = 1s) */
    scale_window = 1;
    name.len = 0;

    for (i = 2; i < cf->args->nelts; i++) {

        if (ngx_strncmp(value[i].data, "zone=", 5) == 0) {

            name.data = value[i].data + 5;

            p = (u_char *) ngx_strchr(name.data, ':');

            if (p == NULL) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid zone size \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            name.len = p - name.data;

            s.data = p + 1;
            s.len = value[i].data + value[i].len - s.data;

            size = ngx_parse_size(&s);

            if (size == NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid zone size \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            if (size < (ssize_t) (8 * ngx_pagesize)) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "zone \"%V\" is too small", &value[i]);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "window=", 7) == 0) {

            len = value[i].len;
            p = value[i].data + len - 2;

            if (ngx_strncmp(p, "ms", 2) == 0) {
                scale_window = 1;  /* milliseconds */
                len -= 2;

            } else if (*(++p) == 's') {
                scale_window = 1000;  /* seconds to milliseconds */
                len -= 1;

            } else if (*p == 'm') {
                scale_window = 60000;  /* minutes to milliseconds */
                len -= 1;

            } else if (*p == 'h') {
                scale_window = 3600000;  /* hours to milliseconds */
                len -= 1;
            }

            window = (ngx_msec_int_t)(ngx_atoi(value[i].data + 7, len - 7)
                                      * scale_window);
            if (window <= 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid window size \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "rate=", 5) == 0) {

            rate = ngx_atoi(value[i].data + 5, value[i].len - 5);
            if (rate <= 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid rate \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[i]);
        return NGX_CONF_ERROR;
    }


    if (name.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"%V\" must have \"zone\" parameter",
                           &cmd->name);
        return NGX_CONF_ERROR;
    }

    shm_zone = ngx_shared_memory_add(cf, &name, size,
                                     &ngx_http_limit_req_freq_module);
    if (shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    if (shm_zone->data) {
        ctx = shm_zone->data;

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "%V \"%V\" is already bound to key \"%V\"",
                           &cmd->name, &name, &ctx->key.value);
        return NGX_CONF_ERROR;
    }

    shm_zone->init = ngx_http_limit_req_freq_init_zone;
    shm_zone->data = ctx;

    ctx->window = window;
    ctx->max_rate = rate * 1000;

    return NGX_CONF_OK;
}


static char *
ngx_http_limit_req_freq(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_limit_req_freq_conf_t  *lrcf = conf;

    ngx_str_t                        *value, s;
    ngx_uint_t                        i;
    ngx_flag_t                        count_rejects;
    ngx_shm_zone_t                   *shm_zone;
    ngx_http_limit_req_freq_limit_t  *limit, *limits;

    value = cf->args->elts;

    shm_zone = NULL;
    count_rejects = 0;

    for (i = 1; i < cf->args->nelts; i++) {

        if (ngx_strncmp(value[i].data, "zone=", 5) == 0) {

            s.len = value[i].len - 5;
            s.data = value[i].data + 5;

            shm_zone = ngx_shared_memory_add(cf, &s, 0,
                                             &ngx_http_limit_req_freq_module);
            if (shm_zone == NULL) {
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "count_rejects", 13) == 0) {

            count_rejects = 1;

            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[i]);
        return NGX_CONF_ERROR;
    }

    if (shm_zone == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"%V\" must have \"zone\" parameter",
                           &cmd->name);
        return NGX_CONF_ERROR;
    }

    limits = lrcf->limits.elts;

    if (limits == NULL) {
        if (ngx_array_init(&lrcf->limits, cf->pool, 1,
                           sizeof(ngx_http_limit_req_freq_limit_t))
            != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }
    }

    for (i = 0; i < lrcf->limits.nelts; i++) {
        if (shm_zone == limits[i].shm_zone) {
            return "is duplicate";
        }
    }

    limit = ngx_array_push(&lrcf->limits);
    if (limit == NULL) {
        return NGX_CONF_ERROR;
    }

    limit->shm_zone = shm_zone;
    limit->count_rejects = count_rejects;

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_limit_req_freq_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

    for (v = ngx_http_limit_req_freq_vars; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_limit_req_freq_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    *h = ngx_http_limit_req_freq_handler;

    return NGX_OK;
}
