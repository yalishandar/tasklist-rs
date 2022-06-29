# tasklist-rs

<p align="center">
    <img height="300" alt="tasklist-rs" src="images/ico.png">
</p>

_a small crate let you can easily get tasklist and process information on windows_

- based on [`windows-rs`](https://github.com/microsoft/windows-rs) crate 

#### what information you can get
1. process name,pid,parrentID,theradsID.
2. process start_time,exit_time,kernel_time,user_time.
3. process path and commandline params.
4. process SID and Domain/User.
5. **TODO** ~~process IO infomation~~ 
6. **TODO** ~~process memory information~~
7. **TODO** ~~process handles information~~
8. tasklist(all process)


## example
```rust
use tasklist;

fn main(){
   
    unsafe{
        let tl = tasklist::Tasklist::new();
        for i in tl{
            println!("{} {} {}",i.get_pid(),i.get_pname(),i.get_user());
        }
    }


}
```

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
tasklist = "0.1.7"
```