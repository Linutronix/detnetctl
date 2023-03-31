///! Helpers for accessing sysrepo
///!
///! These might be later integrated in the sysrepo-rs crate itself.
use anyhow::{anyhow, Result};
use yang2::data::{Data, DataNodeRef};
use yang2::schema::DataValue;

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

impl FromDataValue for String {
    fn try_from_data_value(value: DataValue) -> Result<Self> {
        match value {
            DataValue::Other(x) => Ok(x),
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
        let element = elements.next().ok_or(anyhow!("{} missing", xpath))?;
        assert!(elements.next().is_none());
        let value = element.value().ok_or(anyhow!("{} has no value", xpath))?;
        T::try_from_data_value(value)
    }
}
