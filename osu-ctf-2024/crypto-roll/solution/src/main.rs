
extern crate rand;


use rand::rngs::SmallRng;
use rand::{Rng, SeedableRng};
use std::time::{SystemTime, UNIX_EPOCH};




fn get_roll(value: u64) -> i32 {
    let _seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut rng = SmallRng::seed_from_u64(value);
    rng.gen_range(1..101)
}

fn main() {
    let max_count = 7;
    let mut seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let offset = 40;
    let mut count = 1;
    let mut prev_roll = get_roll(seed + offset);
    while prev_roll + max_count - 1 > 100 {
        seed += 1;
        prev_roll = get_roll(seed + offset);
    }
    println!("Roll {}: {}. Timestamp: {}", 1, prev_roll, seed + offset);
    println!("Prev {}. Next: {}", get_roll(seed + offset - 1), get_roll(seed + offset + 1));
    while count < max_count {
        seed += 1;
        let current_roll = get_roll(seed + offset);
        if current_roll == prev_roll + 1 {
            count += 1;
            prev_roll = current_roll;
            println!("Roll {}: {}. Timestamp: {}", count, prev_roll, (seed + offset));
            println!("Prev {}. Next: {}", get_roll(seed + offset - 1), get_roll(seed + offset + 1));
        }
    }
}
