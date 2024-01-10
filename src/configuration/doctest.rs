// SPDX-FileCopyrightText: 2023 Linutronix GmbH
//
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Only for writing convenient doctests

use tempfile::NamedTempFile;
pub fn generate_example_yaml() -> NamedTempFile {
    use std::io::BufWriter;
    use std::io::Write;

    let file = NamedTempFile::new().expect("Unable to create named temporary file");

    {
        let mut f = BufWriter::new(&file);
        let data = concat!(
            "version: 0.0.1\n",
            "apps:\n",
            "  app0:\n",
            "    logical_interface: eth0.1\n",
            "    physical_interface: eth0\n",
            "    period_ns: 100000\n",
            "    offset_ns: 0\n",
            "    size_bytes: 1000\n",
            "    destination_address: cb:cb:cb:cb:cb:cb\n",
            "    vid: 1\n",
            "    pcp: 2\n");
        f.write_all(data.as_bytes()).expect("Unable to write data");
        f.flush().expect("Flush failed");
    }

    file
}
