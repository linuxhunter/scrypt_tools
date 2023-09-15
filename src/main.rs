use std::sync::Mutex;

use openssl::bn::BigNum;
use openssl::bn::BigNumContext;
use openssl::ec::EcGroup;
use openssl::nid::Nid;
use pbkdf2::pbkdf2_hmac;
use rand::Rng;
//use scrypt::Params;
//use scrypt::scrypt;
use lazy_static::lazy_static;

const PASSWORD: &str = "hello,world!!!";
const SALT: &str = "fd4acb81182a2c8fa959d180967b374277f2ccf2f7f401cb08d042cc785464b4";

lazy_static! {
    static ref M: BigNum = BigNum::from_hex_str("02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f").unwrap();
    static ref N: BigNum = BigNum::from_hex_str("03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49").unwrap();
    static ref W0: Mutex<BigNum> = Mutex::new(BigNum::new().unwrap());
    static ref W1: Mutex<BigNum> = Mutex::new(BigNum::new().unwrap());
    static ref P: Mutex<BigNum> = Mutex::new(BigNum::new().unwrap());
    static ref L: Mutex<BigNum> = Mutex::new(BigNum::new().unwrap());
    static ref RANDOM_X: Mutex<u32> = Mutex::new(0);
    static ref RANDOM_Y: Mutex<u32> = Mutex::new(0);
}

pub fn calculate_scrypt() {
    let mut output = vec![0x00; 80];
    //let params = Params::new(15, 8, 1, 32).unwrap();
    //scrypt(PASSWORD.as_bytes(), SALT.as_bytes(), &params, &mut output).unwrap();
    let n = 32768;
    pbkdf2_hmac::<sha2::Sha512>(PASSWORD.as_bytes(), SALT.as_bytes(), n, &mut output);
    let z0_vec = output[0..40].to_vec();
    let z1_vec = output[40..80].to_vec();

    let nid = Nid::X9_62_PRIME256V1;
    let group = EcGroup::from_curve_name(nid).unwrap();
    let mut ctx = BigNumContext::new().unwrap();
    let mut n = BigNum::new().unwrap();
    let mut n_rem = BigNum::new().unwrap();
    let _ = group.order(&mut n, &mut ctx).unwrap();
    n_rem.checked_sub(&n, &BigNum::from_u32(1).unwrap()).unwrap();
    let z0 = BigNum::from_slice(&z0_vec).unwrap();
    let z1 = BigNum::from_slice(&z1_vec).unwrap();
    let mut tmp_w0 = BigNum::new().unwrap();
    let mut tmp_w1 = BigNum::new().unwrap();
    tmp_w0.checked_rem(&z0, &n_rem, &mut ctx).unwrap();
    tmp_w1.checked_rem(&z1, &n_rem, &mut ctx).unwrap();
    let mut f_w0 = BigNum::new().unwrap();
    let mut f_w1 = BigNum::new().unwrap();
    f_w0.checked_add(&tmp_w0, &BigNum::from_u32(1).unwrap()).unwrap();
    f_w1.checked_add(&tmp_w1, &BigNum::from_u32(1).unwrap()).unwrap();

    let base_point = group.generator();
    let mut x = BigNum::new().unwrap();
    let mut y = BigNum::new().unwrap();
    base_point.affine_coordinates_gfp(&group, &mut x, &mut y, &mut ctx).unwrap();
    let mut p = P.lock().unwrap();
    *p = x;

    let mut w0 = W0.lock().unwrap();
    *w0 = f_w0;
    let mut w1 = W1.lock().unwrap();
    *w1 = f_w1;

    let mut tmp_l = BigNum::new().unwrap();
    tmp_l.checked_mul(&w1, &p, &mut ctx).unwrap();
    let mut l = L.lock().unwrap();
    *l = tmp_l;

    println!("w0 = {}", *w0.to_hex_str().unwrap());
    println!("w1 = {}", *w1);
    println!("P = {:02X?}", *p);
    println!("M = {:02X?}", *M);
    println!("N = {:02X?}", *N);
    println!("L = {}", *l.to_hex_str().unwrap());
}

pub fn calculate_p_b() -> BigNum {
    let mut rng = rand::thread_rng();
    let y = rng.gen::<u32>();
    let mut random_y = RANDOM_Y.lock().unwrap();
    *random_y = y;
    let mut ctx = BigNumContext::new().unwrap();

    let mut tmp_y = BigNum::new().unwrap();
    tmp_y.checked_mul(&P.lock().unwrap(), &BigNum::from_u32(y).unwrap(), &mut ctx).unwrap();

    let mut tmp_n = BigNum::new().unwrap();
    tmp_n.checked_mul(&N, &W0.lock().unwrap(), &mut ctx).unwrap();

    let mut p_b = BigNum::new().unwrap();
    p_b.checked_add(&tmp_y, &tmp_n).unwrap();
    p_b
}

pub fn calculate_p_a() -> BigNum {
    let mut rng = rand::thread_rng();
    let x = rng.gen::<u32>();
    let mut random_x = RANDOM_X.lock().unwrap();
    *random_x = x;
    let mut ctx = BigNumContext::new().unwrap();

    let mut tmp_x = BigNum::new().unwrap();
    tmp_x.checked_mul(&P.lock().unwrap(), &BigNum::from_u32(x).unwrap(), &mut ctx).unwrap();

    let mut tmp_m = BigNum::new().unwrap();
    tmp_m.checked_mul(&M, &W0.lock().unwrap(), &mut ctx).unwrap();

    let mut p_a = BigNum::new().unwrap();
    p_a.checked_add(&tmp_x, &tmp_m).unwrap();
    p_a
}

pub fn verify_p_b(p_b: BigNum) {
    let h = 1;
    let x = *RANDOM_X.lock().unwrap();
    let mut ctx = BigNumContext::new().unwrap();

    let mut tmp_n = BigNum::new().unwrap();
    tmp_n.checked_mul(&W0.lock().unwrap(), &N, &mut ctx).unwrap();

    let mut tmp_z = BigNum::new().unwrap();
    tmp_z.checked_sub(&p_b, &tmp_n).unwrap();

    let mut ec_z = BigNum::new().unwrap();
    ec_z.checked_mul(&BigNum::from_u32(h*x).unwrap(), &tmp_z, &mut ctx).unwrap();
    let mut ec_v = BigNum::new().unwrap();
    ec_v.checked_mul(&W1.lock().unwrap(), &tmp_z, &mut ctx).unwrap();

    println!("[p_b] ec_z = {:?}", ec_z);
    println!("[p_b] ec_v = {:?}", ec_v);
}

pub fn verify_p_a(p_a: BigNum) {
    let h = 1;
    let y = *RANDOM_Y.lock().unwrap();
    let mut ctx = BigNumContext::new().unwrap();

    let mut tmp_m = BigNum::new().unwrap();
    tmp_m.checked_mul(&W0.lock().unwrap(), &M, &mut ctx).unwrap();

    let mut tmp_z = BigNum::new().unwrap();
    tmp_z.checked_sub(&p_a, &tmp_m).unwrap();

    let mut ec_z = BigNum::new().unwrap();
    ec_z.checked_mul(&BigNum::from_u32(h*y).unwrap(), &tmp_z, &mut ctx).unwrap();
    let mut ec_v = BigNum::new().unwrap();
    ec_v.checked_mul(&L.lock().unwrap(), &BigNum::from_u32(h*y).unwrap(), &mut ctx).unwrap();

    println!("[p_a] ec_z = {:?}", ec_z);
    println!("[p_a] ec_v = {:?}", ec_v);
}

fn main() {
    calculate_scrypt();
    let p_b = calculate_p_b();
    let p_a = calculate_p_a();
    verify_p_b(p_b);
    verify_p_a(p_a);
}
