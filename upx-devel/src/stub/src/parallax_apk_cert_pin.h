/*
 * Optional Android APK v2/v3 signer certificate pin for the ARM64 folded
 * ELF-SO loader.  No JNI/PackageManager responses or injected Java classes.
 *
 * This is a defensive identity comparison, NOT a full APK v2/v3 signature
 * verifier.  Android's package installer authenticates signatures on install.
 * On rooted devices file I/O and process memory are not trustworthy.
 *
 * No libc dependency; all file operations use raw syscalls from the stub.
 */
#if defined(__aarch64__)
#define PARALLAX_PIN_MAX_APK_SIGN_BLOCK (8u * 1024u * 1024u)
#define PARALLAX_PIN_MAX_APK_PATH 1024u
#define PARALLAX_PIN_MAX_CERT (128u * 1024u)
#define PARALLAX_PIN_V2 0x7109871au
#define PARALLAX_PIN_V3 0xf05368c0u
#define PARALLAX_PIN_V31 0x1b93ad61u

extern long parallax_lseek(int fd, long offset, int whence);
extern long parallax_pread64(int fd, void *buf, size_t count, unsigned long offset);
static unsigned parallax_pin_u32(unsigned char const *s) {
    return (unsigned)s[0] | ((unsigned)s[1]<<8) | ((unsigned)s[2]<<16) | ((unsigned)s[3]<<24);
}
static uint64_t parallax_pin_u64(unsigned char const *s) {
    return (uint64_t)parallax_pin_u32(s) | ((uint64_t)parallax_pin_u32(s+4)<<32);
}
static uint32_t parallax_pin_rotr(uint32_t n, unsigned r) {
    return (n>>r) | (n<<(32u-r));
}
typedef struct {
    uint32_t h[8];
    uint64_t n;
    unsigned char buf[64];
    unsigned used;
} ParallaxPinSha;
static void parallax_pin_sha_block(ParallaxPinSha *s, unsigned char const *data) {
    static const uint32_t k[64] = {
        0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,
        0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
        0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,
        0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
        0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,
        0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
        0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,
        0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
        0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,
        0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
        0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,
        0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
        0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,
        0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
        0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,
        0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
    };
    uint32_t w[64], a,b,c,d,e,f,g,h;
    unsigned i;
    for (i=0;i<16;i++) {
        unsigned off=4u*i;
        w[i]=((uint32_t)data[off]<<24)|((uint32_t)data[off+1]<<16)|
            ((uint32_t)data[off+2]<<8)|((uint32_t)data[off+3]);
    }
    for (i=16;i<64;i++) {
        uint32_t x=w[i-15], y=w[i-2];
        w[i]=(parallax_pin_rotr(y,17)^parallax_pin_rotr(y,19)^(y>>10))+
             w[i-7]+(parallax_pin_rotr(x,7)^parallax_pin_rotr(x,18)^(x>>3))+w[i-16];
    }
    a=s->h[0];b=s->h[1];c=s->h[2];d=s->h[3];
    e=s->h[4];f=s->h[5];g=s->h[6];h=s->h[7];
    for(i=0;i<64;i++) {
        uint32_t t1=h+(parallax_pin_rotr(e,6)^parallax_pin_rotr(e,11)^parallax_pin_rotr(e,25))+
            ((e&f)^((~e)&g))+k[i]+w[i];
        uint32_t t2=(parallax_pin_rotr(a,2)^parallax_pin_rotr(a,13)^parallax_pin_rotr(a,22))+
            ((a&b)^(a&c)^(b&c));
        h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
    }
    s->h[0]+=a;s->h[1]+=b;s->h[2]+=c;s->h[3]+=d;
    s->h[4]+=e;s->h[5]+=f;s->h[6]+=g;s->h[7]+=h;
}
static void parallax_pin_sha_init(ParallaxPinSha *s) {
    static const uint32_t initial[8]={
        0x6a09e667u,0xbb67ae85u,0x3c6ef372u,0xa54ff53au,
        0x510e527fu,0x9b05688cu,0x1f83d9abu,0x5be0cd19u};
    unsigned i;
    for(i=0;i<8;i++)s->h[i]=initial[i];
    s->n=0;s->used=0;
}
static void parallax_pin_sha_update(ParallaxPinSha *s, unsigned char const *p, size_t n) {
    size_t i;
    s->n+=(uint64_t)n;
    for(i=0;i<n;i++) {
        s->buf[s->used++]=p[i];
        if(s->used==64u) {
            parallax_pin_sha_block(s,s->buf);
            s->used=0;
        }
    }
}
static void parallax_pin_sha_final(ParallaxPinSha *s, unsigned char digest[32]) {
    uint64_t bits=s->n*8u;
    unsigned i;
    unsigned char z=0,lead=0x80u;
    parallax_pin_sha_update(s,&lead,1);
    while(s->used!=56u)parallax_pin_sha_update(s,&z,1);
    for(i=0;i<8;i++){
        unsigned char c=(unsigned char)(bits>>((7u-i)*8u));
        parallax_pin_sha_update(s,&c,1);
    }
    for(i=0;i<8;i++){
        digest[4*i]=(unsigned char)(s->h[i]>>24);
        digest[4*i+1]=(unsigned char)(s->h[i]>>16);
        digest[4*i+2]=(unsigned char)(s->h[i]>>8);
        digest[4*i+3]=(unsigned char)s->h[i];
    }
}
static int parallax_pin_cert_equal(unsigned char const *cert,size_t len,
                                   unsigned char const expected[32]) {
    ParallaxPinSha s;
    unsigned char actual[32];
    unsigned i, diff=0;
    /* Reject malformed DER certificate framing before hashing. */
    if(len<4u || len>PARALLAX_PIN_MAX_CERT || cert[0]!=0x30u)return 0;
    if(cert[1]<0x80u) {
        if((size_t)cert[1]+2u!=len)return 0;
    } else {
        unsigned n=(unsigned)(cert[1]&0x7fu), j;
        size_t body=0;
        if(n==0u || n>4u || 2u+n>=len)return 0;
        if(cert[2]==0u)return 0; /* non-minimal length */
        for(j=0;j<n;j++)body=(body<<8)|cert[2u+j];
        if(body+2u+n!=len)return 0;
    }
    parallax_pin_sha_init(&s);
    parallax_pin_sha_update(&s,cert,len);
    parallax_pin_sha_final(&s,actual);
    for(i=0;i<32;i++)diff|=(unsigned)(actual[i]^expected[i]);
    return diff==0;
}
typedef struct {unsigned char const *p;size_t len;} ParallaxPinSpan;
static int parallax_pin_lp32(ParallaxPinSpan *cur,ParallaxPinSpan *out) {
    size_t n;
    if(cur->len<4u)return 0;
    n=(size_t)parallax_pin_u32(cur->p);
    if(n>cur->len-4u)return 0;
    out->p=cur->p+4;out->len=n;
    cur->p+=4+n;cur->len-=4+n;
    return 1;
}
/* All listed signers must have the expected signing certificate. */
static int parallax_pin_signers(unsigned char const *p,size_t len,
                               unsigned char const expected[32]){
    ParallaxPinSpan values={p,len}, signers, signer, signed_data, digest_list, cert_list, cert;
    unsigned count=0;
    if(!parallax_pin_lp32(&values,&signers)||values.len!=0)return 0;
    while(signers.len) {
        if(++count>8u||!parallax_pin_lp32(&signers,&signer)||
           !parallax_pin_lp32(&signer,&signed_data)||
           !parallax_pin_lp32(&signed_data,&digest_list)||
           !parallax_pin_lp32(&signed_data,&cert_list)||
           !parallax_pin_lp32(&cert_list,&cert))return 0;
        if(!parallax_pin_cert_equal(cert.p,cert.len,expected))return 0;
        /* X.509 chains may carry intermediates; pin the first (leaf) DER
           certificate and validate the length framing of remaining chain. */
        while(cert_list.len) {
            if(!parallax_pin_lp32(&cert_list,&cert))return 0;
        }
    }
    return count>0u;
}
static int parallax_pin_read(int fd,unsigned char *buf,size_t n,uint64_t off) {
    size_t done=0;
    while(done<n) {
        long got=parallax_pread64(fd,buf+done,n-done,(unsigned long)(off+done));
        if(got<=0)return 0;
        done+=(size_t)got;
    }
    return 1;
}
/*
 * Read APK Signing Block v2/v3 certificate(s) directly from base.apk/split APK.
 * The parsed cert is not accepted as proof that every signed byte is valid;
 * the OS installer is trusted to have authenticated its installed package.
 */
static int parallax_pin_apk_file(char const *path,unsigned char const expected[32]){
    int fd=openat(0,path,O_RDONLY,0), good=0;
    long length;
    unsigned char *tail=(unsigned char *)-1,*block=(unsigned char *)-1;
    size_t tn,i;
    uint64_t cd,block_size;
    int found=0, matched=0;
    if(fd<0)return 0;
    length=parallax_lseek(fd,0,2);
    if(length<22 || length>0x7fffffffffffL)goto finish;
    tn=(size_t)(length<65557 ? length : 65557);
    tail=(unsigned char *)mmap(0,tn,PROT_READ|PROT_WRITE,
        MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    if(tail==(unsigned char *)-1)goto finish;
    if(!parallax_pin_read(fd,tail,tn,(uint64_t)length-tn))goto finish;
    for(i=tn-22;;i--){
        if(parallax_pin_u32(tail+i)==0x06054b50u &&
           i+22u+(size_t)tail[i+20]+((size_t)tail[i+21]<<8)==tn)
            break;
        if(i==0u)goto finish;
    }
    if(tail[i+4]!=0||tail[i+5]!=0||tail[i+6]!=0||tail[i+7]!=0)
        goto finish; /* no multi-disk archives */
    cd=(uint64_t)parallax_pin_u32(tail+i+16);
    if(cd==0xffffffffu || cd<32u || cd>(uint64_t)length)goto finish;
    {
        unsigned char ending[24];
        if(!parallax_pin_read(fd,ending,24,cd-24))goto finish;
        if(ending[8]!='A'||ending[9]!='P'||ending[10]!='K'||ending[11]!=' '||
           ending[12]!='S'||ending[13]!='i'||ending[14]!='g'||ending[15]!=' '||
           ending[16]!='B'||ending[17]!='l'||ending[18]!='o'||ending[19]!='c'||
           ending[20]!='k'||ending[21]!=' '||ending[22]!='4'||ending[23]!='2')
            goto finish;
        block_size=parallax_pin_u64(ending);
    }
    if(block_size<24u || block_size>PARALLAX_PIN_MAX_APK_SIGN_BLOCK||
       block_size+8u>cd)goto finish;
    block=(unsigned char *)mmap(0,(size_t)block_size+8u,
        PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    if(block==(unsigned char *)-1)goto finish;
    if(!parallax_pin_read(fd,block,(size_t)block_size+8u,cd-block_size-8u))goto finish;
    if(parallax_pin_u64(block)!=block_size)goto finish;
    {
        size_t pos=8u, end=(size_t)block_size-16u;
        /* Choose the scheme whose cert corresponds to the active installed
           APK. Requiring all present schemes to match also rejects unexpected
           certificate rotation unless the user re-pins the new certificate. */
        while(pos<end) {
            uint64_t n;
            unsigned id;
            int scheme;
            if(end-pos<12u)goto finish;
            n=parallax_pin_u64(block+pos);
            if(n<4u||n>(uint64_t)(end-pos-8u))goto finish;
            id=parallax_pin_u32(block+pos+8u);
            scheme=(id==PARALLAX_PIN_V2 || id==PARALLAX_PIN_V3 || id==PARALLAX_PIN_V31);
            if(scheme){
                found++;
                if(!parallax_pin_signers(block+pos+12u,(size_t)n-4u,expected))
                    goto finish;
                matched++;
            }
            pos+=(size_t)n+8u;
        }
        if(pos!=end)goto finish;
    }
    good=(found>0 && found==matched);
finish:
    if(block!=(unsigned char *)-1)Punmap(block,(size_t)block_size+8u);
    if(tail!=(unsigned char *)-1)Punmap(tail,tn);
    close(fd);
    return good;
}
/* Only an installed package's APK may provide the signer identity. A copied
 * signed base.apk beside an arbitrary extracted .so is not an identity check
 * on the app actually loading the library. Android 7+ package paths live in
 * /data/app or under an adopted-storage volume's /mnt/expand/.../app.
 */
static int parallax_pin_installed_path(char const *path) {
    char const *p=path;
    char const data[]="/data/app/";
    char const expanded[]="/mnt/expand/";
    unsigned i;
    for(i=0;data[i];++i)if(p[i]!=data[i])break;
    if(!data[i])return p[i]!='\0';
    for(i=0;expanded[i];++i)if(p[i]!=expanded[i])return 0;
    p+=i;
    if(!*p || *p=='/')return 0;
    while(*p && *p!='/')++p;
    return p[0]=='/' && p[1]=='a' && p[2]=='p' && p[3]=='p' &&
           p[4]=='/' && p[5]!='\0';
}
/* Parse the library's own file mapping, not another module's name. */
static int parallax_pin_find_apk(char out[PARALLAX_PIN_MAX_APK_PATH],
                                Elf64_Addr lib_addr) {
    int fd;
    char line[PARALLAX_PIN_MAX_APK_PATH+256];
    size_t n=0;
    char const maps[]="/proc/self/maps";
    fd=openat(0,maps,O_RDONLY,0);
    if(fd<0)return 0;
    for(;;){
        char data[4096];
        ssize_t got=read(fd,data,sizeof(data));
        size_t j;
        if(got<=0)break;
        for(j=0;j<(size_t)got;j++) {
            if(data[j]=='\n') {
                Elf64_Addr lo=0,hi=0;
                if(parallax_parse_hex_range(line,n,&lo,&hi)&&lo<=lib_addr&&lib_addr<hi) {
                    size_t k=0,start=0,slashes=0;
                    while(k<n && line[k]!='/')k++;
                    if(k==n)break;
                    for(;k<n;k++) {
                        if(line[k]==' '||line[k]=='\r'||line[k]=='\n')break;
                        if(slashes+1u>=PARALLAX_PIN_MAX_APK_PATH)break;
                        out[slashes++]=line[k];
                    }
                    out[slashes]=0;
                    if(slashes<9u)break;
                    if(!parallax_pin_installed_path(out))break;
                    /* Already mapped directly from an uncompressed split/base APK. */
                    if(slashes>=4u&&out[slashes-4]=='.'&&out[slashes-3]=='a'&&
                       out[slashes-2]=='p'&&out[slashes-1]=='k'){
                        close(fd);return 1;
                    }
                    /* Extracted native lib under /data/app/.../lib/arm64/. */
                    for(k=0;k+10u<slashes;k++) {
                        if(out[k]=='/'&&out[k+1]=='l'&&out[k+2]=='i'&&
                           out[k+3]=='b'&&out[k+4]=='/'&&
                           out[k+5]=='a'&&out[k+6]=='r'&&out[k+7]=='m'&&
                           out[k+8]=='6'&&out[k+9]=='4'&&out[k+10]=='/'){
                            start=k+1u;break;
                        }
                    }
                    if(start && start+8u<PARALLAX_PIN_MAX_APK_PATH) {
                        out[start]='b';out[start+1]='a';out[start+2]='s';
                        out[start+3]='e';out[start+4]='.';out[start+5]='a';
                        out[start+6]='p';out[start+7]='k';out[start+8]=0;
                        close(fd);return 1;
                    }
                    break;
                }
                n=0;
            }else if(n<sizeof(line)-1u)line[n++]=data[j];
            else n=0;
        }
    }
    close(fd);
    return 0;
}
static int parallax_pin_verify_apk(unsigned char const expected[32],
                                  char const *va_load){
    char path[PARALLAX_PIN_MAX_APK_PATH];
    if(!parallax_pin_find_apk(path,(Elf64_Addr)(uintptr_t)va_load))return 0;
    return parallax_pin_apk_file(path,expected);
}
#endif /* __aarch64__ */
