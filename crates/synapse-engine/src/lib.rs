/// Minimal compatibility type used by the optional ZeroClaw Synapse backend.
#[derive(Debug, Default, Clone, Copy)]
pub struct Engine;

impl Engine {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}
