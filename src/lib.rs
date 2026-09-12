use std::{ffi::CStr, io::Read};

use jni::{Env, objects::JClassLoader};
use ristretto_classfile::{
    ClassFile,
    attributes::{Attribute, Instruction},
};

pub fn get_instance(mut env: Env, name: &str, loader: JClassLoader, buf: &[u8]) {
    let name = name.as_bytes();
    let name = CStr::from_bytes_with_nul(&name).unwrap();
    let name = unsafe { jni::strings::JNIStr::from_cstr_unchecked(name) };
    let a = env.define_class(Some(name), loader, buf).unwrap();
}
pub fn by_name(zip: &str, name: &str) -> Option<Vec<u8>> {
    let mut zip = zip::ZipArchive::new(std::fs::File::open(zip).ok()?).ok()?;
    let mut buf = Vec::new();
    let e = zip.by_name(name).unwrap().read_to_end(&mut buf);
    e.ok()?;
    Some(buf)
}
pub enum MixinInjection {
    Head,
    Tail,
    Redirect,
    Overwrite,
}
pub fn find_memmem(
    zip: &str,
    name: &str,
    class: &str,
    inject: MixinInjection,
    instr: Vec<Instruction>,
) -> Vec<u8> {
    let vec = by_name(zip, name).unwrap();
    let cursor = std::io::Cursor::new(vec);
    let mut cf = ClassFile::from_bytes(&cursor.into_inner()).unwrap();

    for i in 0..cf.methods.len() {
        let method_name = cf
            .constant_pool
            .try_get_utf8(cf.methods[i].name_index)
            .unwrap()
            .to_string();
        if method_name != class {
            continue;
        }

        for attr in cf.methods[i].attributes.iter_mut() {
            let Attribute::Code {
                max_stack,
                code,
                exception_table,
                attributes: code_attrs,
                ..
            } = attr
            else {
                continue;
            };

            match inject {
                MixinInjection::Head => {
                    let mut new_code = instr;
                    new_code.append(code);
                    *code = new_code;
                }
                MixinInjection::Tail => {
                    let at = code
                        .iter()
                        .rposition(|ins| {
                            matches!(
                                ins,
                                Instruction::Ireturn
                                    | Instruction::Lreturn
                                    | Instruction::Freturn
                                    | Instruction::Dreturn
                                    | Instruction::Areturn
                                    | Instruction::Return
                            )
                        })
                        .unwrap_or(code.len());
                    code.splice(at..=at, instr);
                }
                MixinInjection::Redirect => {
                    let at = code.iter().position(|ins| {
                        matches!(
                            ins,
                            Instruction::Invokevirtual(_)
                                | Instruction::Invokespecial(_)
                                | Instruction::Invokestatic(_)
                                | Instruction::Invokeinterface(_, _)
                                | Instruction::Invokedynamic(_)
                        )
                    });
                    if let Some(at) = at {
                        code.splice(at..=at, instr);
                    }
                }
                MixinInjection::Overwrite => {
                    *code = instr;
                    exception_table.clear();
                    code_attrs.clear();
                }
            }

            *max_stack = max_stack.saturating_add(4);
            break;
        }
        break;
    }
    let mut bytes = Vec::new();
    cf.to_bytes(&mut bytes).unwrap();
    bytes
}
#[allow(non_snake_case)]
pub fn Agent_OnLoad(
    vm: *mut jni::sys::JavaVM,
    _options: *const std::os::raw::c_char,
    _reserved: *mut std::os::raw::c_void,
) -> jni::sys::jint {
    ::jvmti_autobindings::jvmtiEnv::
    eprintln!("[crow] Agent_OnLoad");
    jni::sys::JNI_OK
}