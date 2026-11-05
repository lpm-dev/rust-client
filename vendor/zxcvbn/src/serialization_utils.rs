use serde::de::{Deserialize, Deserializer};

pub(crate) fn deserialize_f64_null_as_nan<'de, D: Deserializer<'de>>(
    des: D,
) -> Result<f64, D::Error> {
    let optional = Option::<f64>::deserialize(des)?;
    Ok(optional.unwrap_or(f64::NAN))
}
