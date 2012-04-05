#define FEXPORT_u16(file,x)                                           \
do {                                                                  \
        uint16_t xx = htons((uint16_t) (x));                          \
        fwrite(&xx, 2, 1, file);                                      \
} while (0)

#define FEXPORT_u32(file,x)                                           \
do {                                                                  \
        uint32_t xx = htonl((uint32_t) (x));                          \
        fwrite(&xx, 4, 1, file);                                      \
} while (0)

#define FEXPORT_str(file,x)                                           \
do {                                                                  \
        uint16_t len = strlen(x);                                     \
        FEXPORT_u16(file, len);                                       \
        fwrite(x, len, 1, file);                                      \
} while (0)

#define FIMPORT_u16(file,x)                                           \
do {                                                                  \
        uint16_t xx;                                                  \
        fread(&xx, 2, 1, file);                                       \
        x = ntohs(xx);                                                \
} while (0)

#define FIMPORT_u32(file,x)                                           \
do {                                                                  \
        uint32_t xx;                                                  \
        fread(&xx, 4, 1, file);                                       \
        x = ntohl(xx);                                                \
} while (0)

#define FIMPORT_str(file,x,len)                                       \
do {                                                                  \
        FIMPORT_u16(file,len);                                        \
        x = malloc(len+1);                                            \
        fread(x, len, 1, file);                                       \
        x[len] = 0;                                                   \
} while (0)
