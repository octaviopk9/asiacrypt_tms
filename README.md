# Rust Implementaion of Threshold Mercurial Signatures

Library associated with the paper "Interactive Threshold Mercurial Signatures and Applications", a paper accepted at ASIACRYPT 2024. Implemented by Masaya Nanri (@mnanri)

Disclaimer: This implementation has not been reviewed or audited beyond the authors' scrutiny. It is a prototype implementation, developed for academic purposes to validate the algorithms and protocols presented in the related paper. Some sub-routines are naive implementations whose sole purpose is to provide feasibility results. Therefore, this implementation is not intended to be used "as it is" in production and you should use it at your own risk if you wish to do so.

You can run the benchmark code in this project to obtain a detailed report. 

## How to run the benchmark

1. Install Rust programing language following instruction like [this](https://www.rust-lang.org/tools/install). If you install it successfully, you can run `cargo --version` command like this:
```
$ cargo --version
cargo 1.75.0 (1d8b05cdd 2023-11-20) # outputed version is depends on your environment.
```

2. Run the command `cargo build` inside the project's directory to produce the binaries.

3. Run the command `cargo bench` to run the benchmark. Benchmarks are based on Criterion, a benchmarking library. This library will print on your console but for extensive statistical results with plots and easy to navigate, Criterion will generate an HTML report under 'target/criterion/report/index.html' in the project folder. Criterion runs the code you give it a varying amount of iterations, depending on the execution time of every run. In our case it tends to run every function 100 times.

To generate the library's documentation you can run `cargo doc --open`

## Example of result

When you run `cargo bench`, you will get information as in the table shown below (`l` means the number of elements in message and sign key) depending on the hardware and versions used. Besides, you will also get the numbers corresponding to the verification times. 

| Scheme | Parties | Sign(l=1) | Sign(l=5) | Sign(l=10) |
|:-----:|:---:|:----:|:----:|:----:|
|MS|1|0.3|0.4|0.5|
|TMS|2|3.9|6.2|10.1|
|TMS|5|13.3|19.3|29.6|
|TMS|10|28.0|40.8|60.5|
