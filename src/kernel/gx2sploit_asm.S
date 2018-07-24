    .globl set_semaphore_phys
set_semaphore_phys:
    mflr 0
    stwu 1, -0x20(1)
    stw 31, 0x1C(1)
    stw 30, 0x18(1)
    stw 0, 0x24(1)

    mtctr 3
    mr 3, 4
    mr 30, 5
    li 31, 1
    bctr

    .globl Register
Register:
    li 0,0x3200
    sc
    blr

    .globl CopyToSaveArea
CopyToSaveArea:
    li 0,0x4800
    sc
    blr

    .globl SC0x25_SetupSyscall
SC0x25_SetupSyscall:
    li 0,0x2500
    sc
    blr

    .globl SC0x65_ExploitCheck
SC0x65_ExploitCheck:
    li 0,0x6500
    sc
    blr
