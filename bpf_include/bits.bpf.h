#ifndef __BITS_BPF_H__
#define __BITS_BPF_H__

#define READ_ONECE(x) (* (volatile typeof(x)*) &(x) )
#define WRITE_ONECE(x, val) ( (* (volatile typeof(x)*) &(x)) = val)

static __always_inline u64 log2(u32 v){
    u32 r, shift;
    r = (v > 0xffff) << 4; v >>= r;
    shift = (v > 0xff) << 3; r |= shift; v >>= shift;
    shift = (v > 0xf) << 2; r |= shift; v >>= shift;
    shift = (v > 0x3) << 1; r |= shift; v >>= shift;
    r |= (v >> 1);
    return r;
}

static __always_inline u64 log2l(u64 v){
    u32 r = v >> 32;
    if(r){
        return 32 + log2(r);
    }
    return log2(v);
}


#endif