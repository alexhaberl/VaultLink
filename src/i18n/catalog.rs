#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct MessageKey(&'static str);

impl MessageKey {
    pub const fn id(self) -> &'static str {
        self.0
    }
}

#[derive(Clone, Copy)]
struct CatalogEntry {
    key: MessageKey,
    de: &'static str,
    en: &'static str,
}

macro_rules! catalog {
    ($( $name:ident, $id:literal, $de:literal, $en:literal; )+ ) => {
        $(pub const $name: MessageKey = MessageKey($id);)+

        const CATALOG: &[CatalogEntry] = &[
            $(CatalogEntry { key: $name, de: $de, en: $en },)+
        ];
    };
}
