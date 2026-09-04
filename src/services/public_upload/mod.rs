//! Transport-neutral results of the public-upload state machine.
//!
//! Multipart parsing and HTTP presentation deliberately live in `web`; the
//! state machine hands every adapter the same immutable result instead of
//! encoding state in private response headers and parsing it back again.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum UploadDisposition {
    Created,
    CreatedUncertain,
    Replaced,
    ReplacedUncertain,
    DirectoryUncertain,
}

impl UploadDisposition {
    pub(crate) const fn outcome(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::CreatedUncertain => "created_uncertain",
            Self::Replaced => "replaced",
            Self::ReplacedUncertain => "replaced_uncertain",
            Self::DirectoryUncertain => "directory_uncertain",
        }
    }

    pub(crate) const fn redirect_notice(self) -> &'static str {
        match self {
            Self::Created => "ok",
            Self::CreatedUncertain => "uncertain",
            Self::Replaced => "replaced",
            Self::ReplacedUncertain => "replaced_uncertain",
            Self::DirectoryUncertain => "directory_uncertain",
        }
    }

    pub(crate) const fn storage_durability_uncertain(self) -> bool {
        matches!(
            self,
            Self::CreatedUncertain | Self::ReplacedUncertain | Self::DirectoryUncertain
        )
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct PublicUploadSuccess {
    file: String,
    upload_subdir: String,
    disposition: UploadDisposition,
    audit_durability_uncertain: bool,
}

impl PublicUploadSuccess {
    pub(crate) fn new(
        file: String,
        upload_subdir: String,
        disposition: UploadDisposition,
        audit_durability_uncertain: bool,
    ) -> Self {
        Self {
            file,
            upload_subdir,
            disposition,
            audit_durability_uncertain,
        }
    }

    pub(crate) fn file(&self) -> &str {
        &self.file
    }

    pub(crate) fn upload_subdir(&self) -> &str {
        &self.upload_subdir
    }

    pub(crate) const fn disposition(&self) -> UploadDisposition {
        self.disposition
    }

    pub(crate) const fn audit_durability_uncertain(&self) -> bool {
        self.audit_durability_uncertain
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upload_dispositions_keep_the_established_wire_values() {
        let cases = [
            (UploadDisposition::Created, "created", "ok", false),
            (
                UploadDisposition::CreatedUncertain,
                "created_uncertain",
                "uncertain",
                true,
            ),
            (UploadDisposition::Replaced, "replaced", "replaced", false),
            (
                UploadDisposition::ReplacedUncertain,
                "replaced_uncertain",
                "replaced_uncertain",
                true,
            ),
            (
                UploadDisposition::DirectoryUncertain,
                "directory_uncertain",
                "directory_uncertain",
                true,
            ),
        ];
        for (disposition, outcome, notice, uncertain) in cases {
            assert_eq!(disposition.outcome(), outcome);
            assert_eq!(disposition.redirect_notice(), notice);
            assert_eq!(disposition.storage_durability_uncertain(), uncertain);
        }
    }
}
