use anyhow::Result;
use mockall::mock;
use std::sync::Arc;
use std::time::Duration;
use sysrepo;
use yang2::context::Context;
use yang2::data::DataTree;

mock! {
    pub SrConn {
        pub fn new(opts: u32) -> Result<Self, i32>;
        pub fn start_session<'a>(&'a mut self, ds: sysrepo::SrDatastore) -> Result<&'a mut MockSrSession, i32>;
    }
}

mock! {
    pub SrSession {
        pub fn get_data(
            &mut self,
            context: &Arc<Context>,
            xpath: &str,
            max_depth: Option<u32>,
            timeout: Option<Duration>,
            opts: u32
        ) -> Result<MockSrData, i32>;
    }

    impl Clone for SrSession {
        fn clone(&self) -> Self;
    }
}

mock! {
    pub SrData {
        pub fn tree(&self) -> &DataTree;
    }
}
