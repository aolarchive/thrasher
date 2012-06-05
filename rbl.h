typedef struct rbl_negcache {
    uint32_t        addr;
    struct event    timeout;
} rbl_negcache_t;

void rbl_init(void);
void expire_rbl_negcache(int, short, rbl_negcache_t *);
void get_rbl_answer(int, char, int, int, struct in_addr *, uint32_t *);
void make_rbl_query(uint128_t addr);
