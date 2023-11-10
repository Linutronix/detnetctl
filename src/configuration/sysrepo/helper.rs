// SPDX-FileCopyrightText: 2023 Linutronix GmbH
//
// SPDX-License-Identifier: GPL-3.0-or-later
//
//! Helpers for accessing sysrepo
//!
//! These might be later integrated in the sysrepo-rs crate itself.
use anyhow::{anyhow, ensure, Context, Result};
use std::sync::{Arc, Mutex};
use yang2::context::{Context as YangContext, ContextFlags};
use yang2::data::{Data, DataNodeRef, DataTree};
use yang2::schema::DataValue;

#[cfg(not(test))]
use {sysrepo::SrConn, sysrepo::SrSession};

#[cfg(test)]
mod mocks;
#[cfg(test)]
use {mocks::MockSrConn as SrConn, mocks::MockSrSession as SrSession};

/// Reads configuration from sysrepo
pub struct SysrepoReader {
    ctx: Arc<Mutex<SysrepoContext>>,
}

struct SysrepoContext {
    _sr: SrConn, // never used, but referenced by sess
    sess: SrSession,
    libyang_ctx: Arc<YangContext>,
}

#[allow(clippy::non_send_fields_in_send_ty)]
// SAFETY:
// Safety should be taken care of by sysrepo_rs in the future!
unsafe impl Send for SysrepoReader {}

impl SysrepoReader {
    /// Create a new `SysrepoReader` and connect to `sysrepo`
    ///
    /// # Errors
    ///
    /// Will return `Err` if no proper connection can be set up to Sysrepo,
    /// usually because the service is not running.
    pub fn new() -> Result<Self> {
        let ds = sysrepo::SrDatastore::Running;

        sysrepo::log_stderr(sysrepo::SrLogLevel::Debug);

        // Connect to sysrepo
        let Ok(mut sr) = SrConn::new(0) else {
            return Err(anyhow!("Could not connect to sysrepo"));
        };

        // Start session
        let Ok(sess) = sr.start_session(ds) else {
            return Err(anyhow!("Could not start sysrepo session"));
        };
        let unowned_sess = sess.clone();

        // Setup libyang context
        let libyang_ctx =
            YangContext::new(ContextFlags::NO_YANGLIBRARY).context("Failed to create context")?;
        let libyang_ctx = Arc::new(libyang_ctx);

        Ok(Self {
            ctx: Arc::new(Mutex::new(SysrepoContext {
                _sr: sr,
                sess: unowned_sess,
                libyang_ctx,
            })),
        })
    }

    pub fn get_config(&mut self, xpath: &str) -> Result<DataTree> {
        let mut lock = self
            .ctx
            .lock()
            .or(Err(anyhow!("Poisoned Sysrepo Context")))?;
        let context = &mut *lock;
        context
            .sess
            .get_data(&context.libyang_ctx, xpath, None, None, 0)
            .map_err(|e| anyhow!("Can not get sysrepo data: {e}"))
    }
}

pub trait FromDataValue {
    fn try_from_data_value(value: DataValue) -> Result<Self>
    where
        Self: Sized;
}

impl FromDataValue for u8 {
    fn try_from_data_value(value: DataValue) -> Result<Self> {
        match value {
            DataValue::Uint8(x) => Ok(x),
            _ => Err(anyhow!("Type does not match!")),
        }
    }
}

impl FromDataValue for i16 {
    fn try_from_data_value(value: DataValue) -> Result<Self> {
        match value {
            DataValue::Int16(x) => Ok(x),
            _ => Err(anyhow!("Type does not match!")),
        }
    }
}

impl FromDataValue for u16 {
    fn try_from_data_value(value: DataValue) -> Result<Self> {
        match value {
            DataValue::Uint16(x) => Ok(x),
            _ => Err(anyhow!("Type does not match!")),
        }
    }
}

impl FromDataValue for u32 {
    fn try_from_data_value(value: DataValue) -> Result<Self> {
        match value {
            DataValue::Uint32(x) => Ok(x),
            _ => Err(anyhow!("Type does not match!")),
        }
    }
}

impl FromDataValue for u64 {
    fn try_from_data_value(value: DataValue) -> Result<Self> {
        match value {
            DataValue::Uint64(x) => Ok(x),
            _ => Err(anyhow!("Type does not match!")),
        }
    }
}

impl FromDataValue for String {
    fn try_from_data_value(value: DataValue) -> Result<Self> {
        match value {
            DataValue::Other(x) => Ok(x),
            _ => Err(anyhow!("Type does not match!")),
        }
    }
}

impl FromDataValue for bool {
    fn try_from_data_value(value: DataValue) -> Result<Self> {
        match value {
            DataValue::Bool(x) => Ok(x),
            _ => Err(anyhow!("Type does not match!")),
        }
    }
}

pub trait GetValueForXPath {
    fn get_value_for_xpath<T: FromDataValue>(&self, xpath: &str) -> Result<T>;
}

impl GetValueForXPath for DataNodeRef<'_> {
    fn get_value_for_xpath<T: FromDataValue>(&self, xpath: &str) -> Result<T> {
        let mut elements = self.find_xpath(xpath)?;
        let element = elements
            .next()
            .ok_or_else(|| anyhow!("{} missing", xpath))?;
        ensure!(elements.next().is_none(), "expecting only one element");
        let value = element
            .value()
            .ok_or_else(|| anyhow!("{} has no value", xpath))?;
        T::try_from_data_value(value)
            .with_context(|| format!("Converting value for {xpath} failed"))
    }
}
