use flate2::Compression;
use flate2::write::GzEncoder;
use std::io::Write;

pub(crate) fn create_test_tarball(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut tar_data = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_data);
        for (path, content) in files {
            let mut header = tar::Header::new_gnu();
            header.set_size(content.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, format!("package/{path}"), &content[..])
                .unwrap();
        }
        builder.finish().unwrap();
    }
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&tar_data).unwrap();
    encoder.finish().unwrap()
}
