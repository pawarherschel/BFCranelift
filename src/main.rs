extern crate core;

use crate::program::Program;
use capstone::arch::BuildsCapstone as _;
use capstone::arch::BuildsCapstoneSyntax as _;
use capstone::Capstone;
use std::fmt::Write as _;
use std::io::Write as _;

mod program;

// following https://rodrigodd.github.io/2022/11/26/bf_compiler-part3.html
// const SRC: &[u8] = &[b'+'; 72];

const SRC: &[u8] = br#"
[ This program prints "Hello World!" and a newline to the screen; its
  length is 106 active command characters. [It is not the shortest.]

  This loop is an "initial comment loop", a simple way of adding a comment
  to a BF program such that you don't have to worry about any command
  characters. Any ".", ",", "+", "-", "<" and ">" characters are simply
  ignored, the "[" and "]" characters just have to be balanced. This
  loop and the commands it contains are ignored because the current cell
  defaults to a value of 0; the 0 value causes this loop to be skipped.
]
++++++++                Set Cell #0 to 8
[
    >++++               Add 4 to Cell #1; this will always set Cell #1 to 4
    [                   as the cell will be cleared by the loop
        >++             Add 2 to Cell #2
        >+++            Add 3 to Cell #3
        >+++            Add 3 to Cell #4
        >+              Add 1 to Cell #5
        <<<<-           Decrement the loop counter in Cell #1
    ]                   Loop until Cell #1 is zero; number of iterations is 4
    >+                  Add 1 to Cell #2
    >+                  Add 1 to Cell #3
    >-                  Subtract 1 from Cell #4
    >>+                 Add 1 to Cell #6
    [<]                 Move back to the first zero cell you find; this will
                        be Cell #1 which was cleared by the previous loop
    <-                  Decrement the loop Counter in Cell #0
]                       Loop until Cell #0 is zero; number of iterations is 8

The result of this is:
Cell no :   0   1   2   3   4   5   6
Contents:   0   0  72 104  88  32   8
Pointer :   ^

>>.                     Cell #2 has value 72 which is 'H'
>---.                   Subtract 3 from Cell #3 to get 101 which is 'e'
+++++++..+++.           Likewise for 'llo' from Cell #3
>>.                     Cell #5 is 32 for the space
<-.                     Subtract 1 from Cell #4 for 87 to give a 'W'
<.                      Cell #3 was set to 'o' from the end of 'Hello'
+++.------.--------.    Cell #3 for 'rl' and 'd'
>>+.                    Add 1 to Cell #5 gives us an exclamation point
>++.                    And finally a newline from Cell #6
"#;

fn main() {
    let mut program = Program::new(SRC).unwrap();

    program.run();

    let Program { code, memory } = program;

    let cs = Capstone::new()
        .x86()
        .mode(capstone::arch::x86::ArchMode::Mode64)
        .syntax(capstone::arch::x86::ArchSyntax::Att)
        .detail(true)
        .build()
        .unwrap();

    let insns = cs
        .disasm_all(/* &[u8] */ code.as_slice(), /* u64 */ 0x1000)
        .unwrap();

    let mut buf = String::new();

    println!("number of instructions generated: {}", insns.len());

    for i in insns.iter() {
        writeln!(buf, "{i}").unwrap();

        {
            let (name, message) = ("bytes:", format!("{:?}", i.bytes()));
            writeln!(buf, "{:4}{:12} {}", "", name, message).unwrap();
        }
    }

    if std::fs::metadata("cs.txt").is_ok() {
        std::fs::rename("cs.txt", "cs.txt.old").unwrap();
    }
    let mut f = std::fs::File::create("cs.txt").unwrap();
    write!(f, "{buf}").unwrap();

    let not_trailing_zeros = memory.iter().rev().skip_while(|&&v| v == 0).count();

    let memory = memory[0..not_trailing_zeros].to_vec();

    println!("memory: {not_trailing_zeros}");

    println!("{memory:?}");
}
