//! 集成测试目标进程：在已知偏移放置已知值，供 `ce-serve` 跨进程扫描/读写验证。

use std::io::Write;

/// 反复调用的函数（供调试器断点测试）。`#[inline(never)]` 保证它是真实可调用地址。
#[inline(never)]
fn tick() {
    std::hint::black_box(0u64);
}

fn main() {
    let mut data = vec![0u8; 0x2000];
    // x64 分配器返回 8 字节对齐指针，保证 4 字节扫描网格能命中这些偏移。
    data[0x10..0x14].copy_from_slice(&100i32.to_le_bytes()); // 值 100
    data[0x14..0x18].copy_from_slice(&200i32.to_le_bytes()); // 值 200
    data[0x100..0x108].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE]); // AOB
    data[0x200..0x204].copy_from_slice(&777i32.to_le_bytes()); // 值 777

    let ptr = data.as_ptr() as u64;
    // 指针链（供 pointer.scan 测试）：
    //   *(ptr+0x1000) = ptr+0x200  → 直接指向 777 值（offset 0，稳定真指针）
    //   *(ptr+0x1008) = ptr+0x1000 → 二级：指向上面那个指针
    data[0x1000..0x1008].copy_from_slice(&(ptr + 0x200).to_le_bytes());
    data[0x1008..0x1010].copy_from_slice(&(ptr + 0x1000).to_le_bytes());
    // decoy 指针（供二次快照去噪测试）：初始也指向 777 值，2 秒后翻转，模拟随机数据变化
    data[0x1018..0x1020].copy_from_slice(&(ptr + 0x200).to_le_bytes());

    let f: fn() = tick;
    let tick_addr = f as usize as u64;
    println!("ADDR=0x{ptr:x}");
    println!("TICK=0x{tick_addr:x}");
    println!("PID={}", std::process::id());
    let _ = std::io::stdout().flush();

    // 后台线程：2 秒后把 decoy 指针值翻转（模拟随机数据在两次快照间变化）。
    let decoy_addr = ptr + 0x1018;
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_secs(2));
        unsafe {
            *(decoy_addr as *mut u64) = 0xDEAD;
        }
    });

    // 后台线程：周期性写入被监视值（供硬件监视点测试），每 20ms 写一次。
    let watched_addr = ptr + 0x300;
    std::thread::spawn(move || {
        let mut counter: i32 = 0;
        loop {
            counter += 1;
            unsafe {
                *(watched_addr as *mut i32) = counter;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    });

    // 主循环反复调用 tick（供断点测试命中），保持进程存活。
    loop {
        tick();
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}
