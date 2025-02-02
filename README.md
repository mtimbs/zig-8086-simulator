# Learning Zig + CPUs more good

A simple x86 dissasembler + 8086 simulator in Zig

Goal:
- [ ] Learn more about Zig so I can compare it to Odin
- [ ] Learn more about Assembly and how CPUs work in general in the process


## Tools
- Zig 0.13 (https://ziglang.org/download/)
- NASM (converting .asm to binary)(https://www.nasm.us/pub/nasm/releasebuilds/2.16.03/macosx/)


## Resources
- 8086 user manual - https://edge.edx.org/c4x/BITSPilani/EEE231/asset/8086_family_Users_Manual_1_.pdf (page 164 is instruction table)

## Aknowledgements
I am building this as I am following along with the course by C. Muratori at https://www.computerenhance.com


## TODO
- [ ] Opcode patterns in 8086 arithmetic (https://www.computerenhance.com/p/opcode-patterns-in-8086-arithmetic)
- Check the byte/word stuff with immediate to register/memory on MOV. ADD/SUB behave different
 -[x] add
 -[x] subtract
 -[ ] compare
 -[ ] jump not zero
