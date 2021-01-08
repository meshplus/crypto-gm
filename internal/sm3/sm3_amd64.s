//+build !darwin

#include "textflag.h"

#define SS1 ss1-(132*4)(SP)
#define SS2 ss2-(133*4)(SP)
#define TT1 tt1-(134*4)(SP)
#define TT2 tt2-(135*4)(SP)

// Wj = Mj; for 0 <= j <= 15
#define MSGSCHEDULE0(index) \
    CMPQ SI, len1-(136*8)(SP) \
    JNE  2(PC) \
    MOVQ b_base+32(FP), SI \
	MOVL (0)(SI), AX; \
	BSWAPL	AX; \
	MOVL AX, w-((index)*4)(SP) \
    ADDQ $4, SI \
    CMPQ SI, len1-(136*8)(SP) \
    JNE  2(PC) \
    MOVQ b_base+32(FP), SI


// input AX
// output AX = p1(AX)
#define P1() \
    MOVL AX, BX \
    ROLL $15, BX \
    XORL AX, BX \
    ROLL $23, AX \
    XORL BX, AX

// input AX
// output AX = p0(AX)
#define P0() \
    MOVL AX, BX \
    ROLL $9, BX \
    XORL AX, BX \
    ROLL $17, AX \
    XORL BX, AX

// Wj = P1(Wj-16 ^ Wj-9 ^ ((Wj-3)<<<15)) ^ ((Wj-13)<<<7) ^Wj-6; for 16 <= j <= 67
#define MSGSCHEDULE1(index) \
    MOVL w-((index-16)*4)(SP), AX \
    MOVL w-((index-9)*4)(SP), BX \
    XORL AX, BX \ // BX = Wj-16 ^ Wj-9
    MOVL w-((index-3)*4)(SP), AX \
    ROLL $15, AX \
    XORL BX, AX \
    P1()  \
    MOVL w-((index - 13) *4)(SP), BX \
    ROLL $7, BX \
    XORL AX, BX \
    MOVL w-((index -6)* 4)(SP), AX \
    XORL BX, AX \
    MOVL AX, w-((index)*4)(SP)

// 改为使用sha1msg1 指令 ？？？
// Wj = Wj-68 ^ Wj-64
#define MSGSCHEDULE2(index) \
    MOVL w-((index-68)*4)(SP), BX \
    MOVL w-((index-64)*4)(SP), AX \
    XORL BX, AX \
    MOVL AX, w-((index)*4)(SP)
    
// input AX, BX, CX
// output CX = AX ^ BX ^ CX
#define FF1(A, B, C) \
    MOVL A, AX \
    MOVL B, BX \
    MOVL C, CX \
    XORL AX, BX \
    XORL BX, CX

// input AX, BX , CX
// output CX = (AX AND BX) OR (AX AND CX) OR(BX AND CX)
#define FF2(A, B, C) \
    MOVL A, AX \
    MOVL B, BX \
    MOVL C, CX \
    MOVL BX, DX \
    ANDL AX, BX \
    ANDL CX, AX \
    ORL BX, AX \
    ANDL DX, CX \
    ORL AX, CX


// input AX, BX, CX
//output CX = AX ^ BX ^ CX
#define GG1(A, B, C) \
    FF1(A, B, C)

// input AX, BX, CX
//output CX = (AX AND BX) OR (NOT AX AND CX)
#define GG2(A, B, C) \
    MOVL A, AX \
    MOVL B, BX \
    MOVL C, CX \
    ANDL AX, BX \
    NOTL AX \
    ANDL AX, CX \
    ORL BX, CX

#define GenS(index,const,  n, a, e) \
    MOVL a, AX \
    ROLL $12, AX \
    MOVL $const, CX \
    ROLL  $n, CX \
    MOVL e, DX \
    ADDL AX, CX \
    ADDL CX, DX \
    ROLL $7, DX \
    XORL DX, AX \
    MOVL DX, SS1 \
    MOVL AX, SS2


#define GenTT1(index, a, b, c, d, e, f, g, h) \
    FF1(a, b, c) \
    ADDL d, CX \
    ADDL SS2, CX \
    ADDL w-((index+68) * 4)(SP), CX \
    MOVL CX, TT1 \
    GG1(e, f, g) \
    ADDL h, CX \
    ADDL SS1, CX \
    ADDL w-((index)*4)(SP), CX \
    MOVL CX, TT2 \
    ROLL $9, b \
    ROLL $19, f \
    MOVL TT1, h \
    MOVL TT2, AX \
    P0() \
    MOVL AX, d


#define GenTT2(index, a, b, c, d, e, f, g, h) \
    FF2(a, b, c) \
    ADDL d, CX \
    ADDL SS2, CX \
    ADDL w-((index+68) * 4)(SP), CX \
    MOVL CX, TT1 \
    GG2(e, f, g) \
    ADDL h, CX \
    ADDL SS1, CX \
    ADDL w-((index)*4)(SP), CX \
    MOVL CX, TT2 \
    ROLL $9, b \
    ROLL $19, f \
    MOVL TT1, h \
    MOVL TT2, AX \
    P0() \
    MOVL AX, d

//0-11
#define SM3ROUND0(index, n, a, b, c, d, e, f, g, h) \
    MSGSCHEDULE0(index+4) \
    MSGSCHEDULE2(index + 68) \
    GenS(index,0x79cc4519,n, a, e) \
    GenTT1(index, a, b, c, d, e, f, g, h)

// 12-15
#define SM3ROUND1(index, n, a, b, c, d, e, f, g, h) \
    MSGSCHEDULE1(index+4) \
    MSGSCHEDULE2(index + 68) \
    GenS(index,0x79cc4519,n,a, e) \
    GenTT1(index,a, b, c, d, e, f, g, h)

// 16-63
#define SM3ROUND2(index, n, a, b, c, d, e, f, g, h)\
    MSGSCHEDULE1(index+4) \
    MSGSCHEDULE2(index + 68) \
    GenS(index,0x7a879d8a, n, a, e) \
    GenTT2(index,a, b, c, d, e, f, g, h)

//func update(digest *[8]uint32, msg []byte)
TEXT ·update(SB), 0, $16384-32

    MOVQ a_base+8(FP), SI
    MOVQ a_len+16(FP), AX

    LEAQ (SI)(AX*1), DI
    MOVQ DI, len1-(136*8)(SP)

    MOVQ b_len+40(FP), DX


    ADDQ AX, DX
	SHRQ $6, DX
	SHLQ $6, DX

    SUBQ AX, DX

    MOVQ b_base+32(FP), AX
	LEAQ (AX)(DX*1), DI
	MOVQ DI, len2-(137*8)(SP)



    MOVQ dig+0(FP), AX
    MOVL 0(AX),R8
    MOVL 4(AX),R9
    MOVL 8(AX),R10
    MOVL 12(AX),R11
    MOVL 16(AX),R12
    MOVL 20(AX),R13
    MOVL 24(AX),R14
    MOVL 28(AX),R15

loop:
    MSGSCHEDULE0(0)
    MSGSCHEDULE0(1)
    MSGSCHEDULE0(2)
    MSGSCHEDULE0(3)
    SM3ROUND0(0, 0, R8, R9, R10, R11, R12, R13, R14, R15)
    SM3ROUND0(1, 1, R15,R8, R9, R10, R11, R12, R13, R14)
    SM3ROUND0(2, 2, R14, R15, R8, R9, R10, R11, R12, R13)
    SM3ROUND0(3, 3,  R13, R14, R15, R8, R9, R10, R11, R12)
    SM3ROUND0(4, 4, R12, R13, R14, R15, R8, R9, R10, R11)
    SM3ROUND0(5, 5, R11, R12, R13, R14, R15, R8, R9, R10)
    SM3ROUND0(6, 6, R10, R11, R12, R13, R14, R15, R8, R9)
    SM3ROUND0(7, 7, R9, R10, R11, R12, R13, R14, R15, R8)
    SM3ROUND0(8, 8, R8, R9, R10, R11, R12, R13, R14, R15)
    SM3ROUND0(9, 9, R15, R8, R9, R10, R11, R12, R13, R14)
    SM3ROUND0(10, 10, R14, R15, R8, R9, R10, R11, R12, R13)
    SM3ROUND0(11, 11, R13, R14,R15, R8, R9, R10, R11, R12)

    SM3ROUND1(12, 12, R12,R13, R14,R15, R8, R9, R10, R11)
    SM3ROUND1(13, 13, R11,R12,R13, R14,R15, R8, R9, R10)
    SM3ROUND1(14, 14, R10, R11, R12,R13, R14,R15, R8, R9)
    SM3ROUND1(15, 15, R9, R10, R11,R12,R13, R14,R15, R8)

    SM3ROUND2(16, 16, R8, R9, R10, R11,R12,R13, R14,R15)
    SM3ROUND2(17, 17, R15, R8, R9, R10, R11,R12,R13, R14)
    SM3ROUND2(18, 18, R14, R15, R8, R9, R10, R11,R12,R13)
    SM3ROUND2(19, 19, R13, R14, R15, R8, R9, R10, R11,R12)
    SM3ROUND2(20, 20, R12,R13, R14, R15, R8, R9, R10, R11)
    SM3ROUND2(21, 21, R11,R12,R13, R14, R15, R8, R9, R10)
    SM3ROUND2(22, 22, R10, R11,R12,R13, R14, R15, R8, R9)
    SM3ROUND2(23, 23, R9, R10, R11,R12,R13, R14, R15, R8)
    SM3ROUND2(24, 24, R8, R9, R10, R11,R12,R13, R14, R15)
    SM3ROUND2(25, 25, R15, R8, R9, R10, R11,R12,R13, R14)
    SM3ROUND2(26, 26, R14, R15, R8, R9, R10, R11,R12,R13)
    SM3ROUND2(27, 27, R13, R14, R15, R8, R9, R10, R11,R12)
    SM3ROUND2(28, 28, R12,R13, R14,R15, R8, R9, R10, R11)
    SM3ROUND2(29, 29, R11,R12,R13, R14,R15, R8, R9, R10)
    SM3ROUND2(30, 30, R10, R11,R12,R13, R14,R15, R8, R9)
    SM3ROUND2(31, 31, R9, R10, R11,R12,R13, R14, R15, R8)
    SM3ROUND2(32, 0, R8, R9, R10, R11,R12,R13, R14, R15)
    SM3ROUND2(33, 1, R15, R8, R9, R10, R11,R12,R13, R14)
    SM3ROUND2(34, 2, R14, R15, R8, R9, R10, R11,R12,R13)
    SM3ROUND2(35, 3, R13, R14,R15, R8, R9, R10, R11,R12)
    SM3ROUND2(36, 4, R12,R13, R14, R15, R8, R9, R10, R11)
    SM3ROUND2(37, 5, R11,R12,R13, R14,R15, R8, R9, R10)
    SM3ROUND2(38, 6, R10, R11,R12,R13, R14, R15, R8, R9)
    SM3ROUND2(39, 7,  R9, R10, R11,R12,R13, R14, R15, R8)
    SM3ROUND2(40, 8, R8, R9, R10, R11,R12,R13, R14, R15)
    SM3ROUND2(41, 9, R15, R8, R9, R10, R11,R12,R13, R14)
    SM3ROUND2(42, 10, R14,R15,R8, R9, R10, R11,R12,R13)
    SM3ROUND2(43, 11, R13, R14,R15, R8, R9, R10, R11,R12)
    SM3ROUND2(44, 12, R12,R13, R14,R15, R8, R9, R10, R11)
    SM3ROUND2(45, 13, R11,R12,R13, R14, R15, R8, R9, R10)
    SM3ROUND2(46, 14, R10, R11,R12,R13, R14, R15, R8, R9)
    SM3ROUND2(47, 15, R9, R10, R11,R12,R13, R14, R15, R8)
    SM3ROUND2(48, 16, R8, R9, R10, R11,R12,R13, R14, R15)
    SM3ROUND2(49, 17, R15, R8, R9, R10, R11,R12,R13, R14)
    SM3ROUND2(50, 18, R14, R15, R8, R9, R10, R11,R12,R13)
    SM3ROUND2(51, 19, R13, R14, R15, R8, R9, R10, R11,R12)
    SM3ROUND2(52, 20, R12,R13, R14,R15, R8, R9, R10, R11)
    SM3ROUND2(53, 21, R11,R12,R13, R14, R15, R8, R9, R10)
    SM3ROUND2(54, 22, R10, R11,R12,R13, R14, R15, R8, R9)
    SM3ROUND2(55, 23, R9, R10, R11,R12,R13, R14,R15, R8)
    SM3ROUND2(56, 24, R8, R9, R10, R11,R12,R13, R14,R15)
    SM3ROUND2(57, 25, R15, R8, R9, R10, R11,R12,R13, R14)
    SM3ROUND2(58, 26, R14,R15, R8, R9, R10, R11,R12,R13)
    SM3ROUND2(59, 27, R13, R14,R15, R8, R9, R10, R11,R12)
    SM3ROUND2(60, 28, R12,R13, R14,R15, R8, R9, R10, R11)
    SM3ROUND2(61, 29, R11,R12,R13, R14,R15, R8, R9, R10)
    SM3ROUND2(62, 30, R10, R11,R12,R13, R14, R15, R8, R9)
    SM3ROUND2(63, 31, R9, R10, R11,R12,R13, R14,R15, R8)

    MOVQ dig+0(FP), AX
    XORL (0*4)(AX), R8  // H0 = a ^ H0
    MOVL R8, (0*4)(AX)
    XORL (1*4)(AX), R9  // H1 = b ^ H1
    MOVL R9, (1*4)(AX)
    XORL (2*4)(AX), R10 // H2 = c ^ H2
    MOVL R10, (2*4)(AX)
    XORL (3*4)(AX), R11 // H3 = d ^ H3
    MOVL R11, (3*4)(AX)
    XORL (4*4)(AX), R12 // H4 = e ^ H4
    MOVL R12, (4*4)(AX)
    XORL (5*4)(AX), R13 // H5 = f ^ H5
    MOVL R13, (5*4)(AX)
    XORL (6*4)(AX), R14 // H6 = g ^ H6
    MOVL R14, (6*4)(AX)
    XORL (7*4)(AX), R15 // H7 = h ^ H7
    MOVL R15, (7*4)(AX)
    //ADDQ $64, SI
    CMPQ SI, len2-(137*8)(SP)
    JNE  loop


end:
    RET




