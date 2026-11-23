# gfxstream's API descriptions

`renderControl`, `gles1` and `gles2` `.in`, `.attrib` and `.types` are
gfxstream's (`platform/hardware/google/gfxstream`, `codegen/`, at the tag
`android-17.0.0_r1`, the release of the image this protocol is checked
against), unchanged. They are Apache-2.0, Copyright The Android Open Source
Project. emugen, gfxstream's generator, makes the guest's encoders and the
host's decoders from them; `build.rs` here makes the decoder's tables from
them the same way (`codegen/generic-apigen/README` describes the formats).

`gex.types` is gex's own: what the files above leave out but the image's
encoder (`guest/renderControl_enc/renderControl_enc.cpp` at the same tag,
which is checked in) encodes. `rcGetDisplayColorTransform` and
`rcSetDisplayColorTransform` take a `mat4x4_ptr`, a `float*` in
`renderControl_types.h`, which the encoder sends as an `in` pointer of 512
bytes.
