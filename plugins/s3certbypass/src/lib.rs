use skyline::hooks::{getRegionAddress, Region};
use skyline::patching::Patch;

const SPLATOON_3_TITLE_ID: u64 = 0x0100_C250_0FC2_0000;
const MOV_W10_TRUE: u32 = 0x5280_002A;
const LDRB_W10_MASK: u32 = 0xFFC0_001F;
const LDRB_W10_VALUE: u32 = 0x3940_000A;

// The signature begins one instruction after the patch target. Relocated ADR
// operands and register-allocation bytes are wildcarded. This lets us detect a
// target that an old build-ID IPS already changed to MOV W10, #1.
const SIGNATURE: [u8; 28] = [
    0x1F, 0x20, 0x03, 0xD5, // NOP
    0x00, 0x00, 0x00, 0x00, // ADR (relocated)
    0x1F, 0x20, 0x03, 0xD5, // NOP
    0x00, 0x00, 0x00, 0x00, // ADR (relocated)
    0x00, 0x03, 0x00, 0xAA, // MOV X0, Xn (register wildcard)
    0x21, 0x00, 0x80, 0x52, // MOV W1, #1
    0x5F, 0x01, 0x00, 0x71, // CMP W10, #0
];

const SIGNATURE_MASK: [u8; 28] = [
    0xFF, 0xFF, 0xFF, 0xFF,
    0x00, 0x00, 0x00, 0x00,
    0xFF, 0xFF, 0xFF, 0xFF,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0xFF, 0x00, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
];

fn signature_matches(candidate: &[u8]) -> bool {
    SIGNATURE
        .iter()
        .zip(SIGNATURE_MASK.iter())
        .zip(candidate.iter())
        .all(|((&expected, &mask), &actual)| mask == 0 || expected == actual)
}

unsafe fn locate_patch_target() -> Result<usize, &'static str> {
    let text = getRegionAddress(Region::Text) as usize;
    let rodata = getRegionAddress(Region::Rodata) as usize;
    if rodata <= text || rodata - text < SIGNATURE.len() + 4 {
        return Err("invalid main text bounds");
    }

    let image = core::slice::from_raw_parts(text as *const u8, rodata - text);
    let mut found = None;
    let mut count = 0usize;

    // AArch64 instructions are four-byte aligned. The target is the instruction
    // immediately before the signature.
    for signature_offset in (4..=image.len() - SIGNATURE.len()).step_by(4) {
        let candidate = &image[signature_offset..signature_offset + SIGNATURE.len()];
        if signature_matches(candidate) {
            count += 1;
            found = Some(signature_offset - 4);
            if count > 1 {
                return Err("certificate signature is ambiguous");
            }
        }
    }

    found.ok_or("certificate signature was not found")
}

fn apply_certificate_patch() -> Result<&'static str, &'static str> {
    let target_offset = unsafe { locate_patch_target()? };
    let text = unsafe { getRegionAddress(Region::Text) as *const u8 };
    let original = unsafe { (text.add(target_offset) as *const u32).read_volatile() };

    if original == MOV_W10_TRUE {
        return Ok("certificate bypass was already applied");
    }

    if original & LDRB_W10_MASK != LDRB_W10_VALUE {
        return Err("signature matched but target is not LDRB W10");
    }

    Patch::in_text(target_offset)
        .data(MOV_W10_TRUE)
        .map_err(|_| "Skyline could not write the certificate instruction")?;

    let patched = unsafe { (text.add(target_offset) as *const u32).read_volatile() };
    if patched != MOV_W10_TRUE {
        return Err("certificate instruction failed post-write verification");
    }

    Ok("certificate bypass applied")
}

#[skyline::main(name = "s3certbypass")]
pub fn main() {
    let title_id = skyline::info::get_program_id();
    println!(
        "[s3certbypass] plugin started; title_id={title_id:016X}"
    );

    if title_id != SPLATOON_3_TITLE_ID {
        println!("[s3certbypass] ERROR: refusing to patch an unexpected title");
        return;
    }

    match apply_certificate_patch() {
        Ok(message) => println!("[s3certbypass] OK: {message}"),
        Err(message) => println!("[s3certbypass] ERROR: {message}; no patch was written"),
    }
}
