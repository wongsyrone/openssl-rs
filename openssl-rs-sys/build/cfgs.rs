pub fn get(openssl_version: Option<u64>) -> Vec<&'static str> {
    let mut cfgs = vec![];

        let openssl_version = openssl_version.unwrap();

        if openssl_version >= 0x3_00_00_00_0 {
            cfgs.push("ossl300");
        }
        if openssl_version >= 0x1_01_01_03_0 {
            cfgs.push("ossl111c");
        }
        if openssl_version >= 0x1_01_01_02_0 {
            cfgs.push("ossl111b");
        }
        if openssl_version >= 0x1_01_01_00_0 {
            cfgs.push("ossl111");
        }

    cfgs
}
