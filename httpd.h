void fill_current_connections(client_conn_t * conn, struct evbuffer *buf);
gboolean fill_http_blocks(void *key, blocked_node_t * val, struct evbuffer *buf);
void httpd_put_hips(struct evhttp_request *req, void *args);
void httpd_put_connections(struct evhttp_request *req, void *args);
void httpd_put_config(struct evhttp_request *req, void *args);
void httpd_driver(struct evhttp_request *req, void *arg);
int webserver_init(void);
