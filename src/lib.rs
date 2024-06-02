use std::ptr::null;

fn compushady_naga_get_utf8(ptr: *const u8, len: usize) -> String {
    return unsafe { std::str::from_utf8_unchecked(std::slice::from_raw_parts(ptr, len)) }
        .to_string();
}

fn compushady_naga_get_source(
    source_ptr: *const u8,
    source_len: usize,
    output_len: *mut usize,
    error_ptr: *mut *const u8,
    error_len: *mut usize,
) -> String {
    unsafe {
        *output_len = 0;
        *error_ptr = null();
        *error_len = 0;
    };
    return compushady_naga_get_utf8(source_ptr, source_len);
}

fn compushady_naga_module_to_hlsl(
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

fn compushady_naga_module_to_spv(
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
    let source = compushady_naga_get_source(source_ptr, source_len, hlsl_len, error_ptr, error_len);
    match naga::front::wgsl::parse_str(&source) {
        Err(e) => {
            let error_slice = e.emit_to_string(&source).into_bytes().into_boxed_slice();
            unsafe {
                *error_len = error_slice.len();
                *error_ptr = Box::into_raw(error_slice) as *const u8;
            }
        }
        Ok(module) => {
            return compushady_naga_module_to_hlsl(
                &module, &source, hlsl_len, error_ptr, error_len,
            );
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
    let source = compushady_naga_get_source(source_ptr, source_len, hlsl_len, error_ptr, error_len);
    match naga::front::glsl::Frontend::default().parse(
        &naga::front::glsl::Options {
            stage: naga::ShaderStage::Compute,
            defines: Default::default(),
        },
        &source,
    ) {
        Err(e) => {
            let error_slice = e.emit_to_string(&source).into_bytes().into_boxed_slice();
            unsafe {
                *error_len = error_slice.len();
                *error_ptr = Box::into_raw(error_slice) as *const u8;
            }
        }
        Ok(module) => {
            return compushady_naga_module_to_hlsl(
                &module, &source, hlsl_len, error_ptr, error_len,
            );
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
    let source = compushady_naga_get_source(source_ptr, source_len, spv_len, error_ptr, error_len);
    match naga::front::glsl::Frontend::default().parse(
        &naga::front::glsl::Options {
            stage: naga::ShaderStage::Compute,
            defines: Default::default(),
        },
        &source,
    ) {
        Err(e) => {
            let error_slice = e.emit_to_string(&source).into_bytes().into_boxed_slice();
            unsafe {
                *error_len = error_slice.len();
                *error_ptr = Box::into_raw(error_slice) as *const u8;
            }
        }
        Ok(module) => {
            return compushady_naga_module_to_spv(&module, &source, spv_len, error_ptr, error_len);
        }
    }

    return null();
}

#[no_mangle]
pub extern "C" fn compushady_naga_wgsl_to_spv(
    source_ptr: *const u8,
    source_len: usize,
    spv_len: *mut usize,
    error_ptr: *mut *const u8,
    error_len: *mut usize,
) -> *const u8 {
    let source = compushady_naga_get_source(source_ptr, source_len, spv_len, error_ptr, error_len);
    match naga::front::wgsl::parse_str(&source) {
        Err(e) => {
            let error_slice = e.emit_to_string(&source).into_bytes().into_boxed_slice();
            unsafe {
                *error_len = error_slice.len();
                *error_ptr = Box::into_raw(error_slice) as *const u8;
            }
        }
        Ok(module) => {
            return compushady_naga_module_to_spv(&module, &source, spv_len, error_ptr, error_len);
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

#[cfg(test)]
mod tests {
    use crate::{
        compushady_naga_get_utf8, compushady_naga_glsl_to_hlsl, compushady_naga_wgsl_to_hlsl,
        compushady_naga_wgsl_to_spv,
    };

    #[test]
    fn glsl_to_hlsl() {
        let source = "#version 450

        layout(local_size_x = 64, local_size_y = 1, local_size_z = 1) in;
        
        layout(set = 0, binding = 0) buffer Data {
            uint data[];
        } buf;
        
        void main() {
            const uint idx = gl_GlobalInvocationID.x;
            buf.data[idx] = idx * 2;
        }";
        let source_bytes = source.as_bytes();
        let mut hlsl_len: usize = 0;
        let mut error_ptr: *const u8 = std::ptr::null_mut();
        let mut error_len: usize = 0;
        let hlsl_ptr = compushady_naga_glsl_to_hlsl(
            source_bytes.as_ptr(),
            source_bytes.len(),
            &mut hlsl_len,
            &mut error_ptr,
            &mut error_len,
        );

        let hlsl_string = compushady_naga_get_utf8(hlsl_ptr, hlsl_len);

        assert_eq!(error_len, 0);
        assert!(hlsl_len > 0);
        assert!(hlsl_string.contains("[numthreads(64, 1, 1)]"));
    }

    #[test]
    fn wgsl_ray_query_to_spv() {
        let source = "@group(0) @binding(0)
        var acc_struct: acceleration_structure;
        
        struct Output {
            visible: u32,
            normal: vec3<f32>,
        }
        
        @group(0) @binding(1)
        var<storage, read_write> output: Output;
        
        @compute @workgroup_size(1)
        fn main() {
            var rq: ray_query;
        
            let dir = vec3<f32>(0.0, 1.0, 0.0);
            rayQueryInitialize(&rq, acc_struct, RayDesc(RAY_FLAG_TERMINATE_ON_FIRST_HIT, 0xFFu, 0.1, 100.0, vec3<f32>(0.0), dir));
        
            while (rayQueryProceed(&rq)) {}
        
            let intersection = rayQueryGetCommittedIntersection(&rq);
            output.visible = u32(intersection.kind == RAY_QUERY_INTERSECTION_NONE);
            output.normal = vec3<f32>(0, 0, 1);
        }";
        let source_bytes = source.as_bytes();
        let mut spv_len: usize = 0;
        let mut error_ptr: *const u8 = std::ptr::null_mut();
        let mut error_len: usize = 0;
        let _ = compushady_naga_wgsl_to_spv(
            source_bytes.as_ptr(),
            source_bytes.len(),
            &mut spv_len,
            &mut error_ptr,
            &mut error_len,
        );

        assert!(error_len == 0);
        assert!(spv_len > 0);
    }

    #[test]
    fn wgsl_simple_to_spv() {
        let source = "@group(0) @binding(0) var output: texture_storage_2d<rgba32float, write>;
        
        @compute @workgroup_size(7)
        fn main() {
            textureStore(output, vec2<u32>(0, 0), vec4<f32>(0.1, 0.2, 0.3, 1));
        }";
        let source_bytes = source.as_bytes();
        let mut spv_len: usize = 0;
        let mut error_ptr: *const u8 = std::ptr::null_mut();
        let mut error_len: usize = 0;
        let _ = compushady_naga_wgsl_to_spv(
            source_bytes.as_ptr(),
            source_bytes.len(),
            &mut spv_len,
            &mut error_ptr,
            &mut error_len,
        );

        assert!(error_len == 0);
        assert!(spv_len > 0);
    }

    #[test]
    fn wgsl_simple_to_hlsl() {
        let source = "@group(0) @binding(0) var output: texture_storage_2d<rgba32float, write>;
        
        @compute @workgroup_size(4, 5, 6)
        fn main() {
            textureStore(output, vec2<u32>(0, 0), vec4<f32>(0.1, 0.2, 0.3, 1));
        }";
        let source_bytes = source.as_bytes();
        let mut hlsl_len: usize = 0;
        let mut error_ptr: *const u8 = std::ptr::null_mut();
        let mut error_len: usize = 0;
        let hlsl_ptr = compushady_naga_wgsl_to_hlsl(
            source_bytes.as_ptr(),
            source_bytes.len(),
            &mut hlsl_len,
            &mut error_ptr,
            &mut error_len,
        );

        let hlsl_string = compushady_naga_get_utf8(hlsl_ptr, hlsl_len);

        assert_eq!(error_len, 0);
        assert!(hlsl_len > 0);
        assert!(hlsl_string.contains("[numthreads(4, 5, 6)]"));
    }
}
