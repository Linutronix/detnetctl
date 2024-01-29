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
use std::fs::File;
#[cfg(test)]
use yang2::data::{DataFormat, DataParserFlags, DataValidationFlags};
#[cfg(test)]
use {mocks::MockSrConn as SrConn, mocks::MockSrSession as SrSession};

/// Reads configuration from sysrepo
pub(crate) struct SysrepoReader {
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
    pub(crate) fn new() -> Result<Self> {
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

    #[cfg(test)]
    pub(crate) fn mock_from_file(file: &str) -> Self {
        let sr = SrConn::default();
        let mut sess = SrSession::default();
        let mut libyang_ctx =
            YangContext::new(ContextFlags::NO_YANGLIBRARY).expect("Failed to create context");
        libyang_ctx
            .set_searchdir("./config/yang")
            .expect("Failed to set YANG search directory");

        let modules = &[
            ("iana-if-type", vec![]),
            ("ietf-ip", vec![]),
            ("ietf-if-extensions", vec!["sub-interfaces"]),
            ("ietf-detnet", vec![]),
            ("tsn-interface-configuration", vec![]),
            ("ieee1588-ptp", vec![]),
        ];

        for (module_name, features) in modules {
            libyang_ctx
                .load_module(module_name, None, features)
                .expect("Failed to load module");
        }

        let libyang_ctx = Arc::new(libyang_ctx);

        let filename = String::from(file);
        sess.expect_get_data()
            .returning(move |context, _xpath, _max_depth, _timeout, _opts| {
                let tree = DataTree::parse_file(
                    context,
                    File::open(filename.clone()).expect("file not found"),
                    DataFormat::JSON,
                    DataParserFlags::STRICT,
                    DataValidationFlags::NO_STATE,
                )
                .expect("could not parse");

                Ok(tree)
            });

        Self {
            ctx: Arc::new(Mutex::new(SysrepoContext {
                _sr: sr,
                sess,
                libyang_ctx,
            })),
        }
    }

    pub(crate) fn get_config(&mut self, xpath: &str) -> Result<DataTree> {
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

pub(crate) trait FromDataValue {
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

pub(crate) trait GetValueForXPath {
    /// Get the value for this `XPath`.
    ///
    /// Assumes the `XPath` points to a single value. If there are multiple
    /// matches, an error is return.
    ///
    /// Returns Ok(None) if either there is no match for the `XPath`
    /// or there is no associated value for the match.
    fn get_value_for_xpath<T: FromDataValue>(&self, xpath: &str) -> Result<Option<T>>;
}

impl GetValueForXPath for DataNodeRef<'_> {
    fn get_value_for_xpath<T: FromDataValue>(&self, xpath: &str) -> Result<Option<T>> {
        let mut elements = self.find_xpath(xpath)?;

        Ok(elements
            .next()
            .map(|element| {
                ensure!(elements.next().is_none(), "expecting only one element");

                element
                    .value()
                    .map(|value| {
                        T::try_from_data_value(value)
                            .with_context(|| format!("Converting value for {xpath} failed"))
                    })
                    .transpose()
            })
            .transpose()?
            .flatten())
    }
}
