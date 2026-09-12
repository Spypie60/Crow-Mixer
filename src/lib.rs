use std::{
    collections::HashMap,
    ffi::{CStr, c_char, c_void},
    io::{Cursor, Read},
    mem::{size_of, zeroed},
    ptr,
    sync::{Mutex, OnceLock},
};

use jni::sys::{JNI_ERR, JNI_OK, JavaVM, jint};
use jvmti_autobindings::{
    JVMTI_VERSION_1_2, jvmtiCapabilities, jvmtiEnv, jvmtiError, jvmtiError_JVMTI_ERROR_NONE,
    jvmtiEvent_JVMTI_EVENT_CLASS_FILE_LOAD_HOOK, jvmtiEventCallbacks, jvmtiEventMode_JVMTI_DISABLE,
    jvmtiEventMode_JVMTI_ENABLE, jvmtiInterface_1_,
};
use ristretto_classfile::{
    ClassFile,
    attributes::{Attribute, Instruction},
};

// ── mixin registry ─────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug)]
pub enum MixinInjection {
    Head,
    Tail,
    Redirect,
    Overwrite,
}

#[derive(Clone, Debug)]
pub struct Mixin {
    pub method: String,
    pub inject: MixinInjection,
    pub instr: Vec<Instruction>,
}

struct JvmtiPtr(*mut jvmtiEnv);
unsafe impl Send for JvmtiPtr {}
unsafe impl Sync for JvmtiPtr {}

/// JVMTI name → mixins, e.g. `"net/minecraft/client/Minecraft"`
static MIXINS: OnceLock<Mutex<HashMap<String, Vec<Mixin>>>> = OnceLock::new();
/// Unload only. Hook must use the `jvmti` callback argument, never this.
static JVMTI: OnceLock<Mutex<JvmtiPtr>> = OnceLock::new();

fn mixins() -> &'static Mutex<HashMap<String, Vec<Mixin>>> {
    MIXINS.get_or_init(|| Mutex::new(HashMap::new()))
}

pub fn register_mixin(
    class: impl Into<String>,
    method: impl Into<String>,
    inject: MixinInjection,
    instr: Vec<Instruction>,
) {
    mixins()
        .lock()
        .unwrap()
        .entry(class.into())
        .or_default()
        .push(Mixin {
            method: method.into(),
            inject,
            instr,
        });
}

fn parse_class(bytes: &[u8]) -> ClassFile {
    ClassFile::from_bytes(bytes).expect("parse class")
}

pub fn inject_into_class(
    class_bytes: &[u8],
    method: &str,
    inject: MixinInjection,
    instr: Vec<Instruction>,
) -> Vec<u8> {
    let mut cf = parse_class(class_bytes);

    for i in 0..cf.methods.len() {
        let method_name = cf
            .constant_pool
            .try_get_utf8(cf.methods[i].name_index)
            .unwrap()
            .to_string();
        if method_name != method {
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
                    code.splice(at..at, instr);
                }
                MixinInjection::Redirect => {
                    if let Some(at) = code.iter().position(|ins| {
                        matches!(
                            ins,
                            Instruction::Invokevirtual(_)
                                | Instruction::Invokespecial(_)
                                | Instruction::Invokestatic(_)
                                | Instruction::Invokeinterface(_, _)
                                | Instruction::Invokedynamic(_)
                        )
                    }) {
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

    let mut out = Vec::new();
    cf.to_bytes(&mut out).expect("serialize class");
    out
}

pub fn by_name(zip: &str, name: &str) -> Option<Vec<u8>> {
    let mut zip = zip::ZipArchive::new(std::fs::File::open(zip).ok()?).ok()?;
    let mut buf = Vec::new();
    zip.by_name(name).ok()?.read_to_end(&mut buf).ok()?;
    Some(buf)
}

pub fn find_memmem(
    zip: &str,
    entry: &str,
    method: &str,
    inject: MixinInjection,
    instr: Vec<Instruction>,
) -> Vec<u8> {
    let vec = by_name(zip, entry).expect("jar entry missing");
    inject_into_class(&vec, method, inject, instr)
}

// ── jvmti_autobindings helpers ─────────────────────────────────────────────

unsafe fn fns(jvmti: *mut jvmtiEnv) -> &'static jvmti_autobindings::jvmtiInterface_1_ {
    unsafe { &(**jvmti) }
}

unsafe fn jvmti_ok(err: jvmtiError, what: &str) -> bool {
    if err != jvmtiError_JVMTI_ERROR_NONE {
        eprintln!("[crow] {what}: {err}");
        false
    } else {
        true
    }
}

/// `JavaVM` is `*const JNIInvokeInterface_`. `GetEnv` is on that struct, not `.reserved`.
unsafe fn get_jvmti(vm: *mut JavaVM) -> Option<*mut jvmtiEnv> {
    unsafe {
        let mut raw: *mut c_void = ptr::null_mut();
        let get_env = (**vm).reserved.GetEnv;
        let rc = get_env(vm, &mut raw, JVMTI_VERSION_1_2 as jint);
        if rc != JNI_OK || raw.is_null() {
            eprintln!("[crow] GetEnv(JVMTI): {rc}");
            return None;
        }
        Some(raw as *mut jvmtiEnv)
    }
}

unsafe fn add_capabilities(jvmti: *mut jvmtiEnv) -> bool {
    unsafe {
        let mut caps: jvmtiCapabilities = zeroed();
        caps.set_can_generate_all_class_hook_events(1);
        jvmti_ok(
            fns(jvmti).AddCapabilities.unwrap()(jvmti, &caps),
            "AddCapabilities",
        )
    }
}

unsafe fn install_hook(jvmti: *mut jvmtiEnv) -> bool {
    unsafe {
        let mut cb: jvmtiEventCallbacks = zeroed();
        cb.ClassFileLoadHook = std::mem::transmute(on_class_file_load as *const ());
        if !jvmti_ok(
            fns(jvmti).SetEventCallbacks.unwrap()(
                jvmti,
                &cb,
                size_of::<jvmtiEventCallbacks>() as jint,
            ),
            "SetEventCallbacks",
        ) {
            return false;
        }
        jvmti_ok(
            fns(jvmti).SetEventNotificationMode.unwrap()(
                jvmti,
                jvmtiEventMode_JVMTI_ENABLE,
                jvmtiEvent_JVMTI_EVENT_CLASS_FILE_LOAD_HOOK,
                ptr::null_mut(),
            ),
            "enable ClassFileLoadHook",
        )
    }
}

unsafe fn give_bytes(
    jvmti: *mut jvmtiEnv,
    woven: &[u8],
    new_len: *mut jint,
    new_ptr: *mut *mut u8,
) {
    unsafe {
        if new_len.is_null() || new_ptr.is_null() || woven.is_empty() {
            return;
        }
        let mut mem: *mut u8 = ptr::null_mut();
        let err = fns(jvmti).Allocate.unwrap()(jvmti, woven.len() as i64, &mut mem);
        if err != jvmtiError_JVMTI_ERROR_NONE || mem.is_null() {
            eprintln!("[crow] Allocate failed: {err}");
            return;
        }
        ptr::copy_nonoverlapping(woven.as_ptr(), mem, woven.len());
        *new_len = woven.len() as jint;
        *new_ptr = mem;
    }
}

// ── inner Agent_OnLoad (wrapper calls this) ────────────────────────────────

#[allow(non_snake_case)]
pub fn Agent_OnLoad(vm: *mut JavaVM, _options: *mut c_char, _reserved: *mut c_void) -> jint {
    println!("Crow Mixer Loaded");
    if vm.is_null() {
        return JNI_ERR;
    }
    unsafe { agent_on_load_inner(vm) }
}

#[allow(non_snake_case)]
pub fn Agent_OnUnload(_vm: *mut JavaVM, _reserved: *mut c_void) {
    let Some(lock) = JVMTI.get() else { return };
    let Ok(guard) = lock.lock() else { return };
    let jvmti = guard.0;
    unsafe {
        let _ = fns(jvmti).SetEventNotificationMode.unwrap()(
            jvmti,
            jvmtiEventMode_JVMTI_DISABLE,
            jvmtiEvent_JVMTI_EVENT_CLASS_FILE_LOAD_HOOK,
            ptr::null_mut(),
        );
    }
}

unsafe fn agent_on_load_inner(vm: *mut JavaVM) -> jint {
    unsafe {
        let Some(jvmti) = get_jvmti(vm) else {
            return JNI_ERR;
        };
        if !add_capabilities(jvmti) || !install_hook(jvmti) {
            return JNI_ERR;
        }
        let _ = JVMTI.set(Mutex::new(JvmtiPtr(jvmti)));

        // register_mixin(
        //     "net/minecraft/client/Minecraft",
        //     "tick",
        //     MixinInjection::Head,
        //     vec![/* Instruction */],
        // );

        println!("Agent_OnLoad ok");
        JNI_OK
    }
}

unsafe extern "C" fn on_class_file_load(
    jvmti: *mut *const jvmtiInterface_1_,
    _jni: *mut c_void,
    _redefined: *mut c_void,
    _loader: *mut c_void,
    name: *const i8,
    _pd: *mut c_void,
    class_data_len: i32,
    class_data: *const u8,
    new_class_data_len: *mut i32,
    new_class_data: *mut *mut u8,
) {
    if name.is_null() || class_data.is_null() || class_data_len <= 0 {
        return;
    }
    let class_name = unsafe { CStr::from_ptr(name) }.to_string_lossy();
    if class_name.starts_with("net/minecraft/client/") {
        eprintln!("[Crow] {class_name}");
    }

    let jobs = {
        let Ok(map) = mixins().lock() else { return };
        map.get(class_name.as_ref()).cloned()
    };
    let Some(jobs) = jobs else { return };
    if jobs.is_empty() {
        return;
    }

    let mut woven =
        unsafe { std::slice::from_raw_parts(class_data, class_data_len as usize) }.to_vec();
    for job in jobs {
        woven = inject_into_class(&woven, &job.method, job.inject, job.instr);
    }
    unsafe {
        give_bytes(
            jvmti as *mut jvmtiEnv,
            &woven,
            new_class_data_len,
            new_class_data,
        );
    }
}
