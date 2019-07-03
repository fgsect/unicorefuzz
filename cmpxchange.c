int main(void) {
    unsigned int* addr;
    __asm__("" : "=D"(addr));
    unsigned int content_higher = *addr;
    unsigned int content_lower = *(addr+8);
    unsigned int rax, rdx;
    __asm__("" : "=a"(rax), "=d"(rdx) ::);
    if(rax == content_higher && rdx == content_lower) {
        unsigned int rbx, rcx;
        __asm__("" : "=b"(rbx), "=c"(rcx) ::);
        *addr = rbx;
        *(addr+8) = rcx;
        //TODO How to set flags?
    }
}