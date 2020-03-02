use std::fmt;

#[derive(Debug, Copy, Clone)]
pub enum CacheKey {
    PAux,
    TAux,
    CommDTree,
    CommCTree,
    CommRLastTree,
}

impl fmt::Display for CacheKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            CacheKey::PAux => write!(f, "p_aux"),
            CacheKey::TAux => write!(f, "t_aux"),
            CacheKey::CommDTree => write!(f, "tree-d"),
            CacheKey::CommCTree => write!(f, "tree-c"),
            CacheKey::CommRLastTree => write!(f, "tree-r-last"),
        }
    }
}

impl CacheKey {
    pub fn label_layer(layer: usize) -> String {
        format!("layer-{}", layer)
    }
}
