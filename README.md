# tasklist-rs

_a small crate let you can easily get process name or process id on windows_

- based on [`windows-rs`](https://github.com/microsoft/windows-rs) crate 


## example
```rust
use tasklist;

fn main(){
    unsafe{
        //get a HashMap<String,u32> of the tasklist
        let list = tasklist::tasklist();
        println!("{:#?}",list);

        //find the process name by id
        let pname = tasklist::find_process_name_by_id(9720);
        println!("{:#?}",pname);

        //find first process id by name
        let pid = tasklist::find_first_process_id_by_name("cmd.exe");
        println!("{:#?}",pid);

        //find process id by name
        let aid = tasklist::find_process_id_by_name("cmd.exe");
        println!("{:#?}",aid);
    }
    

}
```

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
tasklist = "0.1.5"
```