use cranelift::codegen::ir::{Function, UserFuncName};
use cranelift::codegen::{verify_function, Context};
use cranelift::prelude::{
    isa, settings, types, AbiParam, Configurable, EntityRef, FunctionBuilder,
    FunctionBuilderContext, InstBuilder, IntCC, MemFlags, Signature, Variable,
};
use std::io::{Read, Write};

extern "fastcall" fn write(value: u8) -> *mut std::io::Error {
    // Writing a non-UTF-8 byte sequence on Windows error out.
    if cfg!(target_os = "windows") && value >= 128 {
        return std::ptr::null_mut();
    }

    let mut stdout = std::io::stdout().lock();

    let result = stdout.write_all(&[value]).and_then(|_| stdout.flush());

    match result {
        Err(err) => Box::into_raw(Box::new(err)),
        _ => std::ptr::null_mut(),
    }
}

unsafe extern "fastcall" fn read(buf: *mut u8) -> *mut std::io::Error {
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

const PROGRAM_MEMORY_SIZE: i64 = 30_000;

struct Program {
    code: Vec<u8>,
    memory: [u8; PROGRAM_MEMORY_SIZE as usize],
}

struct UnbalancedBrackets(char, usize);

// PROGRESS: https://rodrigodd.github.io/2022/11/26/bf_compiler-part3.html#fnref:aot:~:text=result%20=%20builder.inst_results(inst)%5B0%5D;-,let%20after_block%20=%20builder.create_block();,-builder.ins().brnz(result%2C%20exit_block%2C%20%26%5Bresult%5D);

impl Program {
    #[allow(clippy::too_many_lines)]
    fn new(source: &[u8]) -> Result<Program, UnbalancedBrackets> {
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

        let mut sig = Signature::new(isa::CallConv::WindowsFastcall);
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
        let wrapped = func_builder
            .ins()
            .iconst(pointer_type, PROGRAM_MEMORY_SIZE - 1);
        func_builder.def_var(pointer, zero);

        let mut stack = vec![];
        let mem_flags = MemFlags::new();

        let (write_sig, write_address) = {
            let mut write_sig = Signature::new(isa::CallConv::WindowsFastcall);
            write_sig.params.push(AbiParam::new(types::I8));
            write_sig.returns.push(AbiParam::new(pointer_type));
            let writer_sig = func_builder.import_signature(write_sig);

            let write_address = write as *const () as i64;
            let write_address = func_builder.ins().iconst(pointer_type, write_address);
            (writer_sig, write_address)
        };
        let (read_sig, read_address) = {
            let mut read_sig = Signature::new(isa::CallConv::WindowsFastcall);
            read_sig.params.push(AbiParam::new(pointer_type));
            read_sig.returns.push(AbiParam::new(pointer_type));
            let read_sig = func_builder.import_signature(read_sig);

            let read_address = read as *const () as i64;
            let read_address = func_builder.ins().iconst(pointer_type, read_address);
            (read_sig, read_address)
        };
        let exit_block = func_builder.create_block();
        func_builder.append_block_param(exit_block, pointer_type);

        for (idx, byte) in source.iter().enumerate() {
            match byte {
                b'+' => {
                    let pointer_value = func_builder.use_var(pointer);
                    let cell_address = func_builder.ins().iadd(memory_address, pointer_value);
                    let cell_value = func_builder
                        .ins()
                        .load(types::I8, mem_flags, cell_address, 0);
                    let cell_value = func_builder.ins().iadd_imm(cell_value, 1);
                    func_builder
                        .ins()
                        .store(mem_flags, cell_value, cell_address, 0);
                }
                b'-' => {
                    let pointer_value = func_builder.use_var(pointer);
                    let cell_address = func_builder.ins().iadd(memory_address, pointer_value);
                    let cell_value = func_builder
                        .ins()
                        .load(types::I8, mem_flags, cell_address, 0);
                    let cell_value = func_builder.ins().iadd_imm(cell_value, -1);
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
                }
                b',' => {}
                b'<' => {
                    let pointer_value = func_builder.use_var(pointer);
                    let pointer_minus = func_builder.ins().iadd_imm(pointer_value, -1);

                    let cmp = func_builder
                        .ins()
                        .icmp_imm(IntCC::SignedLessThan, pointer_minus, 0);
                    let pointer_value = func_builder.ins().select(cmp, wrapped, pointer_minus);

                    func_builder.def_var(pointer, pointer_value);
                }
                b'>' => {
                    let pointer_value = func_builder.use_var(pointer);
                    let pointer_plus = func_builder.ins().iadd_imm(pointer_value, 1);

                    let cmp = func_builder.ins().icmp_imm(
                        IntCC::Equal,
                        pointer_plus,
                        PROGRAM_MEMORY_SIZE,
                    );
                    let pointer_value = func_builder.ins().select(cmp, zero, pointer_plus);

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

                    func_builder.ins().brz(cell_value, after_block, &[]);
                    func_builder.ins().jump(inner_block, &[]);

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

                    func_builder.ins().brz(cell_value, inner_block, &[]);
                    func_builder.ins().jump(after_block, &[]);

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

        func_builder.finalize();
        func_builder.switch_to_block(exit_block);
        func_builder.seal_block(exit_block);

        let result = func_builder.block_params(exit_block)[0];
        func_builder.ins().return_(&[result]);

        let res = verify_function(&func, &*isa);

        if let Err(errors) = res {
            panic!("{errors}");
        }

        let mut ctx = Context::for_function(func);
        let code = match ctx.compile(&*isa) {
            Ok(x) => x,
            Err(err) => {
                eprintln!("error compiling: {err:#?}");
                std::process::exit(0);
            }
        };

        let code = code.code_buffer().to_vec();

        Ok(Program {
            code,
            memory: [0; PROGRAM_MEMORY_SIZE as usize],
        })
    }
}
