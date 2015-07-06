extern crate libc;

use self::Insn::*;
use self::Reg8::*;
use self::Reg16::*;
use self::Reg32::*;
use self::Reg64::*;

pub type Word = u64;

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub struct Symbol(u64);

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
enum Rex {
    NewReg8,
    B,
    W,
    BW,
}

impl Rex {
    fn derive_1<RegX: Reg>(reg: RegX) -> Option<Rex> {
        if reg.code() > 0x7 {
            Some(Rex::B)
        } else {
            None
        }
    }

    fn code(self) -> u8 {
        match self {
            Rex::NewReg8 => 0x40,
            Rex::B => 0x41,
            Rex::W => 0x48,
            Rex::BW => 0x49,
        }
    }
}

impl std::ops::BitOr for Rex {
    type Output = Rex;
    fn bitor(self, other: Rex) -> Rex {
        match (self, other) {
            (Rex::NewReg8, _) => other,
            (_, Rex::NewReg8) => self,
            (Rex::B, Rex::B) => Rex::B,
            (Rex::W, Rex::W) => Rex::W,
            (Rex::B, Rex::W) | (Rex::W, Rex::B) => Rex::BW,
            (Rex::BW, _) => Rex::BW,
            (_ ,Rex::BW) => Rex::BW,
        }
    }
}

pub trait Reg {
    fn code(self) -> u8;
}

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub enum Reg8 {
    Al, Bl, Cl, Dl,
    Ah, Bh, Ch, Dh,
    Spl, Bpl, Sil, Dil,
    R8l, R9l, R10l, R11l,
    R12l, R13l, R14l, R15l,
}

impl Reg for Reg8 {
    fn code(self) -> u8 {
        match self {
            Al => 0x0,
            Cl => 0x1,
            Dl => 0x2,
            Bl => 0x3,
            Ah => 0x4,
            Ch => 0x5,
            Dh => 0x6,
            Bh => 0x7,
            _ => panic!(),
        }
    }
}

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub enum Reg16 {
    Ax, Bx, Cx, Dx,
    Sp, Bp, Si, Di,
    R8w, R9w, R10w, R11w,
    R12w, R13w, R14w, R15w,
}

impl Reg for Reg16 {
    fn code(self) -> u8 {
        match self {
            Ax => 0x0,
            Bx => 0x3,
            Cx => 0x1,
            Dx => 0x2,
            Sp => 0x4,
            Bp => 0x5,
            Si => 0x6,
            Di => 0x7,
            R8w => 0x8,
            R9w => 0x9,
            R10w => 0xa,
            R11w => 0xb,
            R12w => 0xc,
            R13w => 0xd,
            R14w => 0xe,
            R15w => 0xf,
        }
    }
}

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub enum Reg32 {
    Eax, Ebx, Ecx, Edx,
    Esp, Ebp, Esi, Edi,
}

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub enum Reg64 {
    Rax, Rcx, Rdx, Rbx,
    Rsp, Rbp, Rsi, Rdi,
    R8, R9, R10, R11,
    R12, R13, R14, R15,
}

impl Reg for Reg64 {
    fn code(self) -> u8 {
        match self {
            Rax => 0x0,
            Rcx => 0x1,
            Rdx => 0x2,
            Rbx => 0x3,
            Rsp => 0x4,
            Rbp => 0x5,
            Rsi => 0x6,
            Rdi => 0x7,
            R8 => 0x8,
            R9 => 0x9,
            R10 => 0xa,
            R11 => 0xb,
            R12 => 0xc,
            R13 => 0xd,
            R14 => 0xe,
            R15 => 0xf,
        }
    }
}

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
enum Mode {
    Direct,
}

fn encode_modrm_ext<RegX: Reg>(mode: Mode, ext: u8, reg: RegX) -> u8 {
    let mode_bits = match mode {
        Mode::Direct => 0xc0,
    };
    let ext_bits = ext << 3;
    let reg_bits = reg.code() & 0x7;
    mode_bits | ext_bits | reg_bits
}

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub struct Mem8 {
    displacement: u8,
}

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub struct Mem16 {
    displacement: u16,
}

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub struct Mem32 {
    displacement: u32,
}

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub struct Mem64 {
    displacement: u64,
}

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub enum Insn {
    Add8(Reg8, Reg8),
    Add16(Reg16, Reg16),
    Add32(Reg32, Reg32),
    Add64(Reg64, Reg64),

    AddLoad8(Mem8, Reg8),
    AddLoad16(Mem16, Reg16),
    AddLoad32(Mem32, Reg32),
    AddLoad64(Mem64, Reg64),
    AddLoadSym(Symbol, Reg64),

    AddStore8(Reg8, Mem8),
    AddStore16(Reg16, Mem16),
    AddStore32(Reg32, Mem32),
    AddStore64(Reg64, Mem64),
    AddStoreSym(Reg64, Symbol),

    AddLoadImm8(u8, Reg8),
    AddLoadImm16(u16, Reg16),
    AddLoadImm32(u32, Reg32),
    AddLoadImm64(u32, Reg64),

    AddStoreImm8(u8, Mem8),
    AddStoreImm16(u16, Mem8),
    AddStoreImm32(u32, Mem32),
    AddStoreImm64(u32, Mem64),
    AddStoreImmSym(u32, Symbol),

    PushReg16(Reg16),
    PushReg64(Reg64),

    MovLoadImm64(u64, Reg64),

    ReturnNear,
}

impl Insn {
    pub fn encode(&self, buffer: &mut Vec<u8>) {
        match self {
            &PushReg16(reg) => {
                buffer.push(0x66);
                Rex::derive_1(reg).map(|rex| buffer.push(rex.code()));
                buffer.push(reg.code() & 0x7 | 0x50);
            },

            &PushReg64(reg) => {
                Rex::derive_1(reg).map(|rex| buffer.push(rex.code()));
                buffer.push(reg.code() & 0x07 | 0x50);
            }

            &MovLoadImm64(imm, reg) => {
                if let Some(rex) = Rex::derive_1(reg) {
                    buffer.push((rex | Rex::W).code());
                } else {
                    buffer.push(Rex::W.code());
                }
                buffer.push(0xc7);
                buffer.push(encode_modrm_ext(Mode::Direct, 0x00, reg));
                if imm < 0x0000_0001_0000_0000 {
                    buffer.push((imm & 0x0000_00ff) as u8);
                    buffer.push(((imm & 0x0000_ff00) >> 8) as u8);
                    buffer.push(((imm & 0x00ff_0000) >> 16) as u8);
                    buffer.push(((imm & 0xff00_0000) >> 24) as u8);
                } else {
                    panic!();
                }
            }

            &ReturnNear => buffer.push(0xc2),

            _ => panic!(),
        }
    }
}

macro_rules! assert_encode {
    ($insn:expr, $($bytes:expr),+) => {
        {
            let mut buffer = Vec::new();
            ($insn).encode(&mut buffer);
            assert_eq!(buffer, vec![$($bytes),+]);
        }
    }
}

#[test]
fn test_encode_push_16() {
    assert_encode!(PushReg16(Ax), 0x66, 0x50);
    assert_encode!(PushReg16(Bx), 0x66, 0x53);
    assert_encode!(PushReg16(Cx), 0x66, 0x51);
    assert_encode!(PushReg16(Dx), 0x66, 0x52);
    assert_encode!(PushReg16(Sp), 0x66, 0x54);
    assert_encode!(PushReg16(Bp), 0x66, 0x55);
    assert_encode!(PushReg16(Si), 0x66, 0x56);
    assert_encode!(PushReg16(Di), 0x66, 0x57);
    assert_encode!(PushReg16(R8w), 0x66, 0x41, 0x50);
    assert_encode!(PushReg16(R9w), 0x66, 0x41, 0x51);
    assert_encode!(PushReg16(R10w), 0x66, 0x41, 0x52);
    assert_encode!(PushReg16(R11w), 0x66, 0x41, 0x53);
    assert_encode!(PushReg16(R12w), 0x66, 0x41, 0x54);
    assert_encode!(PushReg16(R13w), 0x66, 0x41, 0x55);
    assert_encode!(PushReg16(R14w), 0x66, 0x41, 0x56);
    assert_encode!(PushReg16(R15w), 0x66, 0x41, 0x57);
}

#[test]
fn test_encode_push_64() {
    assert_encode!(PushReg64(Rax), 0x50);
    assert_encode!(PushReg64(Rbx), 0x53);
    assert_encode!(PushReg64(Rcx), 0x51);
    assert_encode!(PushReg64(Rdx), 0x52);
    assert_encode!(PushReg64(Rsp), 0x54);
    assert_encode!(PushReg64(Rbp), 0x55);
    assert_encode!(PushReg64(Rsi), 0x56);
    assert_encode!(PushReg64(Rdi), 0x57);
    assert_encode!(PushReg64(R8), 0x41, 0x50);
    assert_encode!(PushReg64(R9), 0x41, 0x51);
    assert_encode!(PushReg64(R10), 0x41, 0x52);
    assert_encode!(PushReg64(R11), 0x41, 0x53);
    assert_encode!(PushReg64(R12), 0x41, 0x54);
    assert_encode!(PushReg64(R13), 0x41, 0x55);
    assert_encode!(PushReg64(R14), 0x41, 0x56);
    assert_encode!(PushReg64(R15), 0x41, 0x57);
}

#[test]
fn test_encode_return_near() {
    assert_encode!(ReturnNear, 0xc2);
}

#[test]
fn test_encode_mov_load_imm_64() {
    assert_encode!(MovLoadImm64(0, Rax), 0x48, 0xc7, 0xc0, 0x00, 0x00, 0x00, 0x00);
    assert_encode!(MovLoadImm64(1, Rax), 0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00);
    assert_encode!(MovLoadImm64(0x01234567, Rax), 0x48, 0xc7, 0xc0, 0x67, 0x45, 0x23, 0x01);
    assert_encode!(MovLoadImm64(0x01234567, Rbx), 0x48, 0xc7, 0xc3, 0x67, 0x45, 0x23, 0x01);
    assert_encode!(MovLoadImm64(0x01234567, Rcx), 0x48, 0xc7, 0xc1, 0x67, 0x45, 0x23, 0x01);
    assert_encode!(MovLoadImm64(0x01234567, Rdx), 0x48, 0xc7, 0xc2, 0x67, 0x45, 0x23, 0x01);
    assert_encode!(MovLoadImm64(0x01234567, R8), 0x49, 0xc7, 0xc0, 0x67, 0x45, 0x23, 0x01);
}

#[test]
fn lets_run_some_instructions() {
    unsafe {
        use std::mem;
        use std::ptr;

        let mut buffer = vec![];
        MovLoadImm64(42, Rax).encode(&mut buffer);
        ReturnNear.encode(&mut buffer);

        let size = 4 << 10;
        let arena = libc::mmap(
            ptr::null_mut(),
            size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANON,
            -1,
            0,
        );
        ptr::copy_nonoverlapping(buffer.as_ptr(), arena as *mut u8, buffer.len());
        libc::mprotect(arena, size, libc::PROT_READ | libc::PROT_EXEC);
        let function: extern "C" fn() -> u64 = mem::transmute(arena);
        assert_eq!(function(), 42);
        libc::munmap(arena, size);
    }
}
