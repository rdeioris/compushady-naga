use std::ptr::null;

fn compushady_get_source(
    source_ptr: *const u8,
    source_len: usize,
    output_len: *mut usize,
    error_ptr: *mut *const u8,
    error_len: *mut usize,
) -> String {
    return unsafe {
        *output_len = 0;
        *error_ptr = null();
        *error_len = 0;
        std::str::from_utf8_unchecked(std::slice::from_raw_parts(source_ptr, source_len))
            .to_string()
    };
}

fn compushady_module_to_hlsl(
    module: &naga::Module,
    source: &str,
    hlsl_len: *mut usize,
    error_ptr: *mut *const u8,
    error_len: *mut usize,
) -> *const u8 {
    match naga::valid::Validator::new(
        naga::valid::ValidationFlags::all(),
        naga::valid::Capabilities::all(),
    )
    .validate(module)
    {
        Err(e) => {
            let error_slice = e.emit_to_string(source).into_bytes().into_boxed_slice();
            unsafe {
                *error_len = error_slice.len();
                *error_ptr = Box::into_raw(error_slice) as *const u8;
            }
        }
        Ok(info) => {
            let mut buffer = String::new();
            let options = naga::back::hlsl::Options::default();
            let mut writer = naga::back::hlsl::Writer::new(&mut buffer, &options);
            match writer.write(&module, &info) {
                Err(e) => {
                    let error_slice = e.to_string().into_bytes().into_boxed_slice();
                    unsafe {
                        *error_len = error_slice.len();
                        *error_ptr = Box::into_raw(error_slice) as *const u8;
                    }
                }
                Ok(_) => {
                    let slice = buffer.into_bytes().into_boxed_slice();

                    unsafe {
                        *hlsl_len = slice.len();
                    }

                    return Box::into_raw(slice) as *const u8;
                }
            }
        }
    }

    return null();
}

fn compushady_module_to_spv(
    module: &naga::Module,
    source: &str,
    spv_len: *mut usize,
    error_ptr: *mut *const u8,
    error_len: *mut usize,
) -> *const u8 {
    match naga::valid::Validator::new(
        naga::valid::ValidationFlags::all(),
        naga::valid::Capabilities::all(),
    )
    .validate(module)
    {
        Err(e) => {
            let error_slice = e.emit_to_string(source).into_bytes().into_boxed_slice();
            unsafe {
                *error_len = error_slice.len();
                *error_ptr = Box::into_raw(error_slice) as *const u8;
            }
        }
        Ok(info) => {
            match naga::back::spv::write_vec(
                module,
                &info,
                &naga::back::spv::Options::default(),
                Some(&naga::back::spv::PipelineOptions {
                    entry_point: String::from("main"),
                    shader_stage: naga::ShaderStage::Compute,
                }),
            ) {
                Err(e) => {
                    let error_slice = e.to_string().into_bytes().into_boxed_slice();
                    unsafe {
                        *error_len = error_slice.len();
                        *error_ptr = Box::into_raw(error_slice) as *const u8;
                    }
                }
                Ok(spv_vec) => {
                    let slice = spv_vec.into_boxed_slice();

                    unsafe {
                        *spv_len = slice.len();
                    }

                    return Box::into_raw(slice) as *const u8;
                }
            }
        }
    }

    return null();
}

#[no_mangle]
pub extern "C" fn compushady_naga_wgsl_to_hlsl(
    source_ptr: *const u8,
    source_len: usize,
    hlsl_len: *mut usize,
    error_ptr: *mut *const u8,
    error_len: *mut usize,
) -> *const u8 {
    let source = compushady_get_source(source_ptr, source_len, hlsl_len, error_ptr, error_len);
    match naga::front::wgsl::parse_str(&source) {
        Err(e) => {
            let error_slice = e.emit_to_string(&source).into_bytes().into_boxed_slice();
            unsafe {
                *error_len = error_slice.len();
                *error_ptr = Box::into_raw(error_slice) as *const u8;
            }
        }
        Ok(module) => {
            return compushady_module_to_hlsl(&module, &source, hlsl_len, error_ptr, error_len);
        }
    }

    return null();
}

#[no_mangle]
pub extern "C" fn compushady_naga_glsl_to_hlsl(
    source_ptr: *const u8,
    source_len: usize,
    hlsl_len: *mut usize,
    error_ptr: *mut *const u8,
    error_len: *mut usize,
) -> *const u8 {
    let source = compushady_get_source(source_ptr, source_len, hlsl_len, error_ptr, error_len);
    match naga::front::glsl::Frontend::default().parse(
        &naga::front::glsl::Options {
            stage: naga::ShaderStage::Compute,
            defines: Default::default(),
        },
        &source,
    ) {
        Err(e) => {
            let error_slice = e.into_boxed_slice();
            unsafe {
                *error_len = error_slice.len();
                *error_ptr = Box::into_raw(error_slice) as *const u8;
            }
        }
        Ok(module) => {
            return compushady_module_to_hlsl(&module, &source, hlsl_len, error_ptr, error_len);
        }
    }

    return null();
}

#[no_mangle]
pub extern "C" fn compushady_naga_glsl_to_spv(
    source_ptr: *const u8,
    source_len: usize,
    spv_len: *mut usize,
    error_ptr: *mut *const u8,
    error_len: *mut usize,
) -> *const u8 {
    let source = compushady_get_source(source_ptr, source_len, spv_len, error_ptr, error_len);
    match naga::front::glsl::Frontend::default().parse(
        &naga::front::glsl::Options {
            stage: naga::ShaderStage::Compute,
            defines: Default::default(),
        },
        &source,
    ) {
        Err(e) => {
            let error_slice = e.into_boxed_slice();
            unsafe {
                *error_len = error_slice.len();
                *error_ptr = Box::into_raw(error_slice) as *const u8;
            }
        }
        Ok(module) => {
            return compushady_module_to_spv(&module, &source, spv_len, error_ptr, error_len);
        }
    }

    return null();
}

#[no_mangle]
pub extern "C" fn compushady_naga_free(ptr: *mut u8, len: usize) {
    let slice = std::ptr::slice_from_raw_parts_mut(ptr, len);
    unsafe {
        let _ = Box::from_raw(slice);
    };
}
