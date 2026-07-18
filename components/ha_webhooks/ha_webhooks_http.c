 /* This file is part of the WiCAN project.
 *
 * Copyright (C) 2022  Meatpi Electronics.
 * Written by Ali Slim <ali@meatpi.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "ha_webhooks.h"
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>
#include <cJSON.h>
#include <esp_log.h>
#include <esp_http_server.h>
#include <esp_err.h>
#include <lwip/sockets.h>
#include <lwip/netdb.h>

static const char *TAG = "HA_WEBHOOK_HTTP";

/**
 * @brief Check if a URL is valid HTTP or HTTPS
 *
 * @param[in] url URL string to validate
 * @return true if URL starts with "http://" or "https://", false otherwise
 */
static bool url_is_http(const char *url)
{
    if (!url)
        return false;
    return strncmp(url, "http://", 7) == 0 || strncmp(url, "https://", 8) == 0;
}

static void webhook_format_utc(char out[32])
{
    if (!out)
        return;

    time_t now = time(NULL);
    struct tm t;
    memset(&t, 0, sizeof(t));

    if (now <= 0)
    {
        strlcpy(out, "1970-01-01T00:00:00Z", 32);
        return;
    }

    gmtime_r(&now, &t);
    strftime(out, 32, "%Y-%m-%dT%H:%M:%SZ", &t);
}

static void webhook_sanitize_snippet(char *s)
{
    if (!s)
        return;
    for (size_t i = 0; s[i]; i++)
    {
        unsigned char c = (unsigned char)s[i];
        if (c == '\r' || c == '\n' || c == '\t' || c < 32 || c > 126)
            s[i] = ' ';
    }
}

static bool webhook_parse_http_url(const char *url, char *host, size_t host_len, int *out_port, char *path, size_t path_len)
{
    if (!url || !host || !out_port || !path)
        return false;

    if (strncasecmp(url, "http://", 7) != 0)
        return false;

    const char *p = url + 7;
    const char *host_end = p;
    while (*host_end && *host_end != '/' && *host_end != ':')
        host_end++;

    size_t hlen = (size_t)(host_end - p);
    if (hlen == 0 || hlen >= host_len)
        return false;
    memcpy(host, p, hlen);
    host[hlen] = '\0';

    int port = 80;
    const char *after_host = host_end;
    if (*after_host == ':')
    {
        after_host++;
        port = 0;
        while (*after_host && isdigit((unsigned char)*after_host))
        {
            port = (port * 10) + (*after_host - '0');
            after_host++;
        }
        if (port <= 0 || port > 65535)
            return false;
    }

    if (*after_host == '\0')
        strlcpy(path, "/", path_len);
    else if (*after_host == '/')
        strlcpy(path, after_host, path_len);
    else
        return false;

    *out_port = port;
    return true;
}

static esp_err_t webhook_post_json(const char *url, const char *body, size_t body_len, int timeout_ms,
                                   int *out_status, char *out_snippet, size_t out_snippet_len)
{
    if (!url || !body)
        return ESP_ERR_INVALID_ARG;

    if (out_status)
        *out_status = -1;
    if (out_snippet && out_snippet_len)
        out_snippet[0] = '\0';

    char host[96] = {0};
    char path[192] = {0};
    int port = 80;
    if (!webhook_parse_http_url(url, host, sizeof(host), &port, path, sizeof(path)))
        return ESP_ERR_INVALID_ARG;

    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%d", port);

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo *res = NULL;
    int gai = getaddrinfo(host, port_str, &hints, &res);
    if (gai != 0 || !res)
    {
        if (out_snippet && out_snippet_len)
            snprintf(out_snippet, out_snippet_len, "getaddrinfo failed gai=%d", gai);
        return ESP_FAIL;
    }

    int sock = -1;
    int last_errno = 0;
    for (struct addrinfo *ai = res; ai; ai = ai->ai_next)
    {
        sock = (int)socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (sock < 0)
            continue;

        struct timeval tv;
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        if (connect(sock, ai->ai_addr, (socklen_t)ai->ai_addrlen) == 0)
            break;

        last_errno = errno;
        close(sock);
        sock = -1;
    }
    freeaddrinfo(res);

    if (sock < 0)
    {
        if (out_snippet && out_snippet_len)
            snprintf(out_snippet, out_snippet_len, "connect failed errno=%d", last_errno);
        return ESP_FAIL;
    }

    const char *fmt =
        "POST %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Content-Type: application/json\r\n"
        "Connection: close\r\n"
        "Content-Length: %u\r\n"
        "\r\n";

    int hdr_len = snprintf(NULL, 0, fmt, path, host, (unsigned)body_len);
    if (hdr_len <= 0)
    {
        close(sock);
        return ESP_FAIL;
    }

    size_t req_len = (size_t)hdr_len + body_len;
    char *req_buf = (char *)malloc(req_len + 1);
    if (!req_buf)
    {
        close(sock);
        return ESP_ERR_NO_MEM;
    }

    snprintf(req_buf, (size_t)hdr_len + 1, fmt, path, host, (unsigned)body_len);
    memcpy(req_buf + hdr_len, body, body_len);
    req_buf[req_len] = '\0';

    size_t sent = 0;
    while (sent < req_len)
    {
        int n = (int)send(sock, req_buf + sent, (int)(req_len - sent), 0);
        if (n <= 0)
        {
            free(req_buf);
            close(sock);
            return ESP_FAIL;
        }
        sent += (size_t)n;
    }
    free(req_buf);

    char resp[512];
    int r = (int)recv(sock, resp, sizeof(resp) - 1, 0);
    close(sock);
    if (r <= 0)
        return ESP_FAIL;
    resp[r] = '\0';

    int status = -1;
    const char *sp = strstr(resp, "HTTP/");
    if (sp)
    {
        const char *code = strchr(sp, ' ');
        if (code)
            status = atoi(code + 1);
    }
    if (out_status)
        *out_status = status;

    if (out_snippet && out_snippet_len > 0)
    {
        const char *body_start = strstr(resp, "\r\n\r\n");
        body_start = body_start ? (body_start + 4) : resp;
        strlcpy(out_snippet, body_start, out_snippet_len);
        webhook_sanitize_snippet(out_snippet);
    }

    return ESP_OK;
}

/**
 * @brief Send a JSON response to the client
 *
 * Serializes a cJSON object and sends it with appropriate headers and status code.
 * The cJSON object is deleted after sending.
 *
 * @param[in] req HTTP request handle
 * @param[in] obj cJSON object to send (will be deleted by this function)
 * @param[in] status HTTP status code (200, 201, 204, etc.)
 * @return ESP_OK on success, ESP_FAIL on serialization error
 */
static esp_err_t send_json(httpd_req_t *req, cJSON *obj, int status)
{
    char *js = cJSON_PrintUnformatted(obj);
    if (!js)
    {
        ESP_LOGE(TAG, "Failed to serialize JSON response");
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "serialize error");
        cJSON_Delete(obj);
        return ESP_FAIL;
    }

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_status(req, status == 201 ? "201 Created" : status == 200 ? "200 OK"
                                                           : status == 204   ? "204 No Content"
                                                                             : "200 OK");
    httpd_resp_send(req, js, strlen(js));

    ESP_LOGD(TAG, "Sent JSON response (status %d, %zu bytes)", status, strlen(js));

    cJSON_Delete(obj);
    free(js);
    return ESP_OK;
}

/**
 * @brief Handle POST requests to create/update webhook configuration
 *
 * Accepts JSON body with "url" (required) and "enabled" (optional) fields.
 * Returns 201 Created on first configuration, 200 OK on updates.
 *
 * @param[in] req HTTP request handle
 * @return ESP_OK on success, error otherwise
 */
static esp_err_t webhook_post_handler(httpd_req_t *req)
{
    ESP_LOGI(TAG, "POST /api/webhook");

    size_t len = req->content_len;
    ESP_LOGD(TAG, "Request content length: %zu bytes", len);

    if (len == 0 || len > 2048)
    {
        ESP_LOGW(TAG, "Invalid content length: %zu", len);
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "invalid content length");
    }

    char *buf = (char *)malloc(len + 1);
    if (!buf)
    {
        ESP_LOGE(TAG, "Failed to allocate memory for request body");
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "no mem");
    }

    size_t total = 0;
    while (total < len)
    {
        int r = httpd_req_recv(req, buf + total, len - total);
        if (r <= 0)
        {
            ESP_LOGE(TAG, "Failed to receive request body");
            free(buf);
            return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "recv error");
        }
        total += (size_t)r;
    }
    buf[total] = '\0';

    ESP_LOGD(TAG, "Received request body: %s", buf);

    cJSON *root = cJSON_Parse(buf);
    free(buf);

    if (!root)
    {
        ESP_LOGW(TAG, "Invalid JSON in request body");
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "invalid json");
    }

    cJSON *url = cJSON_GetObjectItem(root, "url");
    cJSON *enabled = cJSON_GetObjectItem(root, "enabled");
    cJSON *interval = cJSON_GetObjectItem(root, "interval");

    if (!cJSON_IsString(url) || !url_is_http(url->valuestring))
    {
        ESP_LOGW(TAG, "Invalid or missing URL in request");
        cJSON_Delete(root);
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "invalid url");
    }

    ESP_LOGI(TAG, "Setting webhook URL: %s", url->valuestring);

    // Load current cached config to determine if changes are needed
    ha_webhook_config_t old_cfg = {0};
    esp_err_t have = ha_webhooks_get_config(&old_cfg);
    bool first_set = (have != ESP_OK || old_cfg.url[0] == '\0');

    // Prepare new configuration, preserving fields not controlled here
    ha_webhook_config_t cfg = old_cfg;
    strlcpy(cfg.url, url->valuestring, sizeof(cfg.url));
    cfg.enabled = cJSON_IsBool(enabled) ? cJSON_IsTrue(enabled) : true;
    if (cJSON_IsNumber(interval))
        cfg.interval = interval->valueint;

    if (cfg.enabled)
    {
        strlcpy(cfg.status, "configured", sizeof(cfg.status));
        cfg.retries = 0;
        cfg.last_error[0] = '\0';
        cfg.last_error_time[0] = '\0';
    }
    else
    {
        strlcpy(cfg.status, "disabled", sizeof(cfg.status));
    }

    // Check if meaningful fields actually changed
    bool changed = (strcmp(old_cfg.url, cfg.url) != 0) ||
                   (old_cfg.enabled != cfg.enabled) ||
                   (old_cfg.interval != cfg.interval) ||
                   (strcmp(old_cfg.status, cfg.status) != 0) ||
                   (old_cfg.retries != cfg.retries) ||
                   (strcmp(old_cfg.last_error_time, cfg.last_error_time) != 0) ||
                   (strcmp(old_cfg.last_error, cfg.last_error) != 0);

    ESP_LOGI(TAG, "Webhook %s, enabled: %s", first_set ? "created" : (changed ? "updated" : "unchanged"),
             cfg.enabled ? "yes" : "no");

    // Only save + update cache if configuration changed
    esp_err_t s = ESP_OK;
    if (changed || first_set)
    {
        s = ha_webhooks_set_config(&cfg);
    }
    cJSON_Delete(root);

    if (s != ESP_OK)
    {
        ESP_LOGE(TAG, "Failed to save webhook configuration");
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "save failed");
    }

    cJSON *resp = cJSON_CreateObject();
    cJSON_AddStringToObject(resp, "url", cfg.url);
    cJSON_AddBoolToObject(resp, "enabled", cfg.enabled);
    cJSON_AddNumberToObject(resp, "interval", cfg.interval);

    // Runtime stats (may be zeroed if device hasn't posted yet)
    cJSON_AddNumberToObject(resp, "success_count", cfg.success_count);
    cJSON_AddNumberToObject(resp, "fail_count", cfg.fail_count);
    cJSON_AddStringToObject(resp, "last_error_time", cfg.last_error_time[0] ? cfg.last_error_time : "");
    cJSON_AddStringToObject(resp, "last_error", cfg.last_error[0] ? cfg.last_error : "");

    return send_json(req, resp, first_set ? 201 : 200);
}

/**
 * @brief Handle GET requests to retrieve webhook configuration
 *
 * Returns the current webhook configuration as JSON, including URL,
 * enabled state, last post timestamp, status, and retry count.
 *
 * @param[in] req HTTP request handle
 * @return ESP_OK on success
 */
static esp_err_t webhook_get_handler(httpd_req_t *req)
{
    ESP_LOGI(TAG, "GET /api/webhook");

    ha_webhook_config_t cfg = {0};
    esp_err_t r = ha_webhooks_get_config(&cfg);

    cJSON *resp = cJSON_CreateObject();

    if (r == ESP_OK)
    {
        ESP_LOGI(TAG, "Returning webhook config: URL=%s, enabled=%s, status=%s",
                 cfg.url, cfg.enabled ? "yes" : "no",
                 cfg.status[0] ? cfg.status : "unknown");

        cJSON_AddStringToObject(resp, "url", cfg.url);
        cJSON_AddBoolToObject(resp, "enabled", cfg.enabled);
        cJSON_AddStringToObject(resp, "last_post", cfg.last_post[0] ? cfg.last_post : "");
        cJSON_AddStringToObject(resp, "status", cfg.status[0] ? cfg.status : "unknown");
        cJSON_AddNumberToObject(resp, "retries", cfg.retries);
        cJSON_AddNumberToObject(resp, "interval", cfg.interval);

        cJSON_AddNumberToObject(resp, "success_count", cfg.success_count);
        cJSON_AddNumberToObject(resp, "fail_count", cfg.fail_count);
        cJSON_AddStringToObject(resp, "last_error_time", cfg.last_error_time[0] ? cfg.last_error_time : "");
        cJSON_AddStringToObject(resp, "last_error", cfg.last_error[0] ? cfg.last_error : "");
    }
    else
    {
        ESP_LOGI(TAG, "No webhook configuration found, returning defaults");

        cJSON_AddStringToObject(resp, "url", "");
        cJSON_AddBoolToObject(resp, "enabled", false);
        cJSON_AddStringToObject(resp, "last_post", "");
        cJSON_AddStringToObject(resp, "status", "disabled");
        cJSON_AddNumberToObject(resp, "retries", 0);
        cJSON_AddNumberToObject(resp, "interval", 0);

        cJSON_AddNumberToObject(resp, "success_count", 0);
        cJSON_AddNumberToObject(resp, "fail_count", 0);
        cJSON_AddStringToObject(resp, "last_error_time", "");
        cJSON_AddStringToObject(resp, "last_error", "");
    }

    return send_json(req, resp, 200);
}

static esp_err_t webhook_test_handler(httpd_req_t *req)
{
    ESP_LOGI(TAG, "POST /api/webhook/test");

    ha_webhook_config_t cfg = {0};
    esp_err_t r = ha_webhooks_get_config(&cfg);
    if (r != ESP_OK || cfg.url[0] == '\0')
    {
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "webhook not configured");
    }

    if (!cfg.enabled)
    {
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "webhook disabled");
    }

    if (strncasecmp(cfg.url, "http://", 7) != 0)
    {
        ha_webhook_config_t upd = cfg;
        strlcpy(upd.status, "failed", sizeof(upd.status));
        strlcpy(upd.last_error, "https not supported: use http://", sizeof(upd.last_error));
        webhook_format_utc(upd.last_error_time);
        upd.fail_count++;
        (void)ha_webhooks_update_cache(&upd);
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "https not supported");
    }

    char body[192];
    char now[32];
    webhook_format_utc(now);
    snprintf(body, sizeof(body),
             "{\"source\":\"wican\",\"event\":\"webhook_test\",\"timestamp\":\"%s\"}",
             now);

    int http_status = -1;
    char snippet[96] = {0};
    esp_err_t post_err = webhook_post_json(cfg.url, body, strlen(body), 5000, &http_status, snippet, sizeof(snippet));

    ha_webhook_config_t upd = cfg;
    bool ok = (post_err == ESP_OK && http_status >= 200 && http_status < 300);
    if (ok)
    {
        upd.success_count++;
        upd.retries = 0;
        strlcpy(upd.status, "ok", sizeof(upd.status));
        webhook_format_utc(upd.last_post);
        upd.last_error[0] = '\0';
        upd.last_error_time[0] = '\0';
    }
    else
    {
        upd.fail_count++;
        upd.retries++;
        strlcpy(upd.status, "failed", sizeof(upd.status));
        webhook_format_utc(upd.last_error_time);
        if (http_status > 0)
            snprintf(upd.last_error, sizeof(upd.last_error), "HTTP %d %s", http_status, snippet);
        else if (snippet[0])
            strlcpy(upd.last_error, snippet, sizeof(upd.last_error));
        else
            snprintf(upd.last_error, sizeof(upd.last_error), "%s", esp_err_to_name(post_err));
    }
    (void)ha_webhooks_update_cache(&upd);

    cJSON *resp = cJSON_CreateObject();
    cJSON_AddBoolToObject(resp, "ok", ok);
    cJSON_AddNumberToObject(resp, "http_status", http_status);
    cJSON_AddStringToObject(resp, "url", upd.url);
    cJSON_AddBoolToObject(resp, "enabled", upd.enabled);
    cJSON_AddNumberToObject(resp, "interval", upd.interval);
    cJSON_AddNumberToObject(resp, "success_count", upd.success_count);
    cJSON_AddNumberToObject(resp, "fail_count", upd.fail_count);
    cJSON_AddStringToObject(resp, "status", upd.status);
    cJSON_AddStringToObject(resp, "last_post", upd.last_post[0] ? upd.last_post : "");
    cJSON_AddStringToObject(resp, "last_error_time", upd.last_error_time[0] ? upd.last_error_time : "");
    cJSON_AddStringToObject(resp, "last_error", upd.last_error[0] ? upd.last_error : "");

    return send_json(req, resp, ok ? 200 : 200);
}

/**
 * @brief Handle DELETE requests to remove webhook configuration
 *
 * Clears the webhook configuration by setting URL to empty string,
 * disabling the webhook, and resetting all fields.
 *
 * @param[in] req HTTP request handle
 * @return ESP_OK on success, error otherwise
 */
static esp_err_t webhook_delete_handler(httpd_req_t *req)
{
    ESP_LOGI(TAG, "DELETE /api/webhook - removing webhook configuration");

    // Load existing cached config and only persist if a change is required
    ha_webhook_config_t old_cfg = {0};
    esp_err_t have = ha_webhooks_get_config(&old_cfg);

    ha_webhook_config_t cfg = old_cfg;
    strlcpy(cfg.url, "", sizeof(cfg.url));
    cfg.enabled = false;
    cfg.last_post[0] = '\0';
    strlcpy(cfg.status, "disabled", sizeof(cfg.status));
    cfg.retries = 0;
    cfg.success_count = 0;
    cfg.fail_count = 0;
    cfg.last_error_time[0] = '\0';
    cfg.last_error[0] = '\0';

    bool changed = (old_cfg.url[0] != '\0') || (old_cfg.enabled != false) ||
                   (old_cfg.last_post[0] != '\0') || (strcmp(old_cfg.status, "disabled") != 0) ||
                   (old_cfg.retries != 0) || (old_cfg.interval != 0) ||
                   (old_cfg.success_count != 0) || (old_cfg.fail_count != 0) ||
                   (old_cfg.last_error_time[0] != '\0') || (old_cfg.last_error[0] != '\0') ||
                   (have != ESP_OK);

    if (changed)
    {
        esp_err_t s = ha_webhooks_set_config(&cfg);
        if (s != ESP_OK)
        {
            ESP_LOGE(TAG, "Failed to save cleared webhook configuration");
            return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "save failed");
        }
        ESP_LOGI(TAG, "Webhook configuration deleted successfully");
    }
    else
    {
        ESP_LOGI(TAG, "Webhook configuration already cleared; no write performed");
    }

    httpd_resp_set_status(req, "204 No Content");
    httpd_resp_send(req, NULL, 0);
    return ESP_OK;
}

/**
 * @brief Route incoming requests to appropriate handler
 *
 * Routes requests to the correct HTTP method handler (GET, POST, DELETE)
 * for the /api/webhook endpoint.
 *
 * @param[in] req HTTP request handle
 * @return ESP_OK on success, error otherwise
 */
static esp_err_t router(httpd_req_t *req)
{
    const char *uri = req->uri;

    if (strcmp(uri, "/api/webhook/test") == 0)
    {
        if (req->method == HTTP_POST)
            return webhook_test_handler(req);
        return httpd_resp_send_err(req, HTTPD_405_METHOD_NOT_ALLOWED, "method");
    }

    if (strcmp(uri, "/api/webhook") != 0)
    {
        ESP_LOGW(TAG, "Invalid route requested: %s", uri);
        return httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "route");
    }

    if (req->method == HTTP_POST)
        return webhook_post_handler(req);
    if (req->method == HTTP_GET)
        return webhook_get_handler(req);
    if (req->method == HTTP_DELETE)
        return webhook_delete_handler(req);

    ESP_LOGW(TAG, "Unsupported HTTP method for /api/webhook");
    return httpd_resp_send_err(req, HTTPD_405_METHOD_NOT_ALLOWED, "method");
}

esp_err_t ha_webhooks_register_handlers(httpd_handle_t server)
{
    ESP_LOGI(TAG, "Registering Home Assistant webhook HTTP handlers");

    static const httpd_uri_t get_u = {.uri = "/api/webhook", .method = HTTP_GET, .handler = router};
    static const httpd_uri_t post_u = {.uri = "/api/webhook", .method = HTTP_POST, .handler = router};
    static const httpd_uri_t del_u = {.uri = "/api/webhook", .method = HTTP_DELETE, .handler = router};
    static const httpd_uri_t test_u = {.uri = "/api/webhook/test", .method = HTTP_POST, .handler = router};

    const httpd_uri_t *arr[] = {&get_u, &post_u, &del_u, &test_u};
    const char *method_names[] = {"GET", "POST", "DELETE", "POST test"};

    for (size_t i = 0; i < 4; ++i)
    {
        esp_err_t r = httpd_register_uri_handler(server, arr[i]);
        if (r != ESP_OK && r != ESP_ERR_HTTPD_HANDLER_EXISTS)
        {
            ESP_LOGE(TAG, "Failed to register %s handler: %s", method_names[i], esp_err_to_name(r));
            return r;
        }
        ESP_LOGD(TAG, "Registered %s /api/webhook handler", method_names[i]);
    }

    ESP_LOGI(TAG, "HA webhook handlers registered successfully at /api/webhook");
    return ESP_OK;
}
