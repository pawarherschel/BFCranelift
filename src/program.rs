use cranelift::codegen::control::ControlPlane;
use cranelift::codegen::ir::{Function, UserFuncName};
use cranelift::codegen::{verify_function, Context};
use cranelift::prelude::{
    isa, settings, types, AbiParam, Configurable, EntityRef, FunctionBuilder,
    FunctionBuilderContext, InstBuilder, IntCC, MemFlags, Signature, Variable,
};
use std::io::{Read, Write};

extern "C" fn write(value: u8) -> *mut std::io::Error {
    // Writing a non-UTF-8 byte sequence on Windows error out.
    if cfg!(target_os = "windows") && value >= 128 {
        return std::ptr::null_mut();
    }
    let result = {
        let mut stdout = std::io::stdout().lock();

        stdout.write_all(&[value]).and_then(|()| stdout.flush())
    };

    match result {
        Err(err) => Box::into_raw(Box::new(err)),
        _ => std::ptr::null_mut(),
    }
}

unsafe extern "C" fn read(buf: *mut u8) -> *mut std::io::Error {
    let mut stdin = std::io::stdin().lock();
    loop {
        let mut value = 0;
        let err = stdin.read_exact(std::slice::from_mut(&mut value));

        if let Err(err) = err {
            if err.kind() != std::io::ErrorKind::UnexpectedEof {
                return Box::into_raw(Box::new(err));
            }
            value = 0;
        }

        // ignore CR from Window's CRLF
        if cfg!(target_os = "windows") && value == b'\r' {
            continue;
        }

        *buf = value;

        return std::ptr::null_mut();
    }
}

pub const PROGRAM_MEMORY_SIZE: usize = 30_000;

#[derive(Debug, Clone)]
pub struct Program {
    pub code: Vec<u8>,
    pub memory: [u8; PROGRAM_MEMORY_SIZE],
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct UnbalancedBrackets(pub char, pub usize);

// PROGRESS: https://rodrigodd.github.io/2022/11/26/bf_compiler-part3.html#fnref:aot:~:text=result%20=%20builder.inst_results(inst)%5B0%5D;-,let%20after_block%20=%20builder.create_block();,-builder.ins().brnz(result%2C%20exit_block%2C%20%26%5Bresult%5D);

impl Program {
    #[allow(clippy::too_many_lines)]
    pub fn new(source: &[u8]) -> Result<Self, UnbalancedBrackets> {
        let mut builder = settings::builder();
        builder
            .set("opt_level", "speed")
            .expect("`opt_level` and `speed` should exist");
        let flags = settings::Flags::new(builder);

        let target_triple = target_lexicon::Triple::host();

        let isa = isa::lookup(target_triple)
            .expect("target triple should be supported")
            .finish(flags)
            .unwrap();

        let pointer_type = isa.pointer_type();

        let mut sig = Signature::new(isa::CallConv::triple_default(isa.triple()));
        sig.params.push(AbiParam::new(pointer_type));
        sig.returns.push(AbiParam::new(pointer_type));

        let mut func = Function::with_name_signature(UserFuncName::user(0, 0), sig);

        let mut func_ctx = FunctionBuilderContext::new();
        let mut func_builder = FunctionBuilder::new(&mut func, &mut func_ctx);

        let pointer = Variable::new(0);
        func_builder.declare_var(pointer, pointer_type);

        let func_block = func_builder.create_block();
        func_builder.seal_block(func_block);

        func_builder.append_block_params_for_function_params(func_block);
        func_builder.switch_to_block(func_block);

        let memory_address = func_builder.block_params(func_block)[0];

        let zero = func_builder.ins().iconst(pointer_type, 0);
        func_builder.def_var(pointer, zero);

        let mut stack = vec![];
        let mem_flags = MemFlags::new();

        let (write_sig, write_address) = {
            let mut write_sig = Signature::new(isa::CallConv::triple_default(isa.triple()));
            write_sig.params.push(AbiParam::new(types::I8));
            write_sig.returns.push(AbiParam::new(pointer_type));
            let writer_sig = func_builder.import_signature(write_sig);

            let write_address = write as *const () as i64;
            let write_address = func_builder.ins().iconst(pointer_type, write_address);
            (writer_sig, write_address)
        };
        let (read_sig, read_address) = {
            let mut read_sig = Signature::new(isa::CallConv::triple_default(isa.triple()));
            read_sig.params.push(AbiParam::new(pointer_type));
            read_sig.returns.push(AbiParam::new(pointer_type));
            let read_sig = func_builder.import_signature(read_sig);

            let read_address = read as *const () as i64;
            let read_address = func_builder.ins().iconst(pointer_type, read_address);
            (read_sig, read_address)
        };
        let exit_block = func_builder.create_block();
        func_builder.append_block_param(exit_block, pointer_type);

        let mut ops = source
            .iter()
            .copied()
            .enumerate()
            .filter(|(_, byte)| b"+-><.,[]".contains(byte))
            .peekable();

        while let Some((idx, byte)) = ops.next() {
            match byte {
                b'+' | b'-' => {
                    let mut n = match byte {
                        b'+' => 1,
                        b'-' => -1,
                        _ => unreachable!(),
                    };

                    while ops.peek().map_or(false, |(_, byte)| b"+-".contains(byte)) {
                        let byte = ops.next().unwrap().1;

                        n += match byte {
                            b'+' => 1,
                            b'-' => -1,
                            _ => unreachable!(),
                        };
                    }

                    let pointer_value = func_builder.use_var(pointer);
                    let cell_address = func_builder.ins().iadd(memory_address, pointer_value);
                    let cell_value = func_builder
                        .ins()
                        .load(types::I8, mem_flags, cell_address, 0);
                    let cell_value = func_builder.ins().iadd_imm(cell_value, n);
                    func_builder
                        .ins()
                        .store(mem_flags, cell_value, cell_address, 0);
                }
                b'.' => {
                    let pointer_value = func_builder.use_var(pointer);
                    let cell_address = func_builder.ins().iadd(memory_address, pointer_value);
                    let cell_value = func_builder
                        .ins()
                        .load(types::I8, mem_flags, cell_address, 0);

                    let inst =
                        func_builder
                            .ins()
                            .call_indirect(write_sig, write_address, &[cell_value]);
                    let result = func_builder.inst_results(inst)[0];

                    let after_block = func_builder.create_block();

                    func_builder
                        .ins()
                        .brif(result, exit_block, &[result], after_block, &[]);

                    func_builder.seal_block(after_block);
                    func_builder.switch_to_block(after_block);
                }
                b',' => {
                    let pointer_value = func_builder.use_var(pointer);
                    let cell_address = func_builder.ins().iadd(memory_address, pointer_value);

                    let ins =
                        func_builder
                            .ins()
                            .call_indirect(read_sig, read_address, &[cell_address]);
                    let result = func_builder.inst_results(ins)[0];

                    let after_block = func_builder.create_block();

                    func_builder
                        .ins()
                        .brif(result, exit_block, &[result], after_block, &[]);

                    func_builder.seal_block(after_block);
                    func_builder.switch_to_block(after_block);
                }
                b'<' | b'>' => {
                    let mut n = match byte {
                        b'>' => 1,
                        b'<' => -1,
                        _ => unreachable!(),
                    };

                    while ops.peek().map_or(false, |(_, byte)| b"<>".contains(byte)) {
                        let byte = ops.next().unwrap().1;
                        n += match byte {
                            b'>' => 1,
                            b'<' => -1,
                            _ => unreachable!(),
                        };
                    }

                    let pointer_value = func_builder.use_var(pointer);
                    let pointer_plus = func_builder.ins().iadd_imm(pointer_value, n);

                    let pointer_value = if n > 0 {
                        let wrapped = func_builder.ins().iadd_imm(
                            pointer_value,
                            n - i64::try_from(PROGRAM_MEMORY_SIZE).unwrap(),
                        );
                        let cmp = func_builder.ins().icmp_imm(
                            IntCC::SignedLessThan,
                            pointer_plus,
                            i64::try_from(PROGRAM_MEMORY_SIZE).unwrap(),
                        );
                        func_builder.ins().select(cmp, pointer_plus, wrapped)
                    } else {
                        let wrapped = func_builder.ins().iadd_imm(
                            pointer_value,
                            n + i64::try_from(PROGRAM_MEMORY_SIZE).unwrap(),
                        );
                        let cmp =
                            func_builder
                                .ins()
                                .icmp_imm(IntCC::SignedLessThan, pointer_value, 0);
                        func_builder.ins().select(cmp, wrapped, pointer_plus)
                    };

                    func_builder.def_var(pointer, pointer_value);
                }
                b'[' => {
                    let inner_block = func_builder.create_block();
                    let after_block = func_builder.create_block();

                    let pointer_value = func_builder.use_var(pointer);
                    let cell_address = func_builder.ins().iadd(memory_address, pointer_value);
                    let cell_value = func_builder
                        .ins()
                        .load(types::I8, mem_flags, cell_address, 0);

                    func_builder
                        .ins()
                        .brif(cell_value, inner_block, &[], after_block, &[]);

                    func_builder.switch_to_block(inner_block);

                    stack.push((inner_block, after_block));
                }
                b']' => {
                    let (inner_block, after_block) = match stack.pop() {
                        None => return Err(UnbalancedBrackets(']', idx)),
                        Some(x) => x,
                    };

                    let pointer_value = func_builder.use_var(pointer);
                    let cell_address = func_builder.ins().iadd(memory_address, pointer_value);
                    let cell_value = func_builder
                        .ins()
                        .load(types::I8, mem_flags, cell_address, 0);

                    func_builder
                        .ins()
                        .brif(cell_value, inner_block, &[], after_block, &[]);

                    func_builder.seal_block(inner_block);
                    func_builder.seal_block(after_block);

                    func_builder.switch_to_block(after_block);
                }
                _ => continue,
            }
        }

        if !stack.is_empty() {
            return Err(UnbalancedBrackets(']', source.len()));
        }

        func_builder.ins().return_(&[zero]);

        func_builder.switch_to_block(exit_block);
        func_builder.seal_block(exit_block);

        let result = func_builder.block_params(exit_block)[0];
        func_builder.ins().return_(&[result]);

        func_builder.finalize();

        let res = verify_function(&func, &*isa);

        if let Err(errors) = res {
            panic!("{errors}");
        }

        let clir = func.display().to_string();
        if std::fs::metadata("clir").is_ok() {
            std::fs::rename("clir", "clir.old").unwrap();
        }
        std::fs::write("clir", clir).unwrap();

        let mut ctx = Context::for_function(func);
        let code = match ctx.compile(
            &*isa,
            /* &mut ControlPlane */ &mut ControlPlane::default(),
        ) {
            Ok(x) => x,
            Err(err) => {
                eprintln!("error compiling: {err:#?}");
                std::process::exit(0);
            }
        };

        let code = code.code_buffer().to_vec();

        Ok(Self {
            code,
            memory: [0; PROGRAM_MEMORY_SIZE],
        })
    }

    pub fn run(&mut self) {
        let mut buffer = memmap2::MmapOptions::new()
            .len(self.code.len())
            .map_anon()
            .unwrap();

        buffer.copy_from_slice(self.code.as_slice());

        let buffer = buffer.make_exec().unwrap();

        let code_fn: unsafe extern "C" fn(*mut u8) -> *mut std::io::Error =
            unsafe { std::mem::transmute(buffer.as_ptr()) };

        let error = unsafe { code_fn(self.memory.as_mut_ptr()) };

        assert!(error.is_null(), "{error:#?}");
    }
}
