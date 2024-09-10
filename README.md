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
- [ ] handle dynamically parsing number of bytes (e.g single byte instructions, hi/lo displacement, multiple instructions etc)
- [ ] change diff to work on the machine code not .asm files (handles comments and signed integers)
- [ ] handle movs from more_movs.asm
- [ ] handle challenge_mov.asm
