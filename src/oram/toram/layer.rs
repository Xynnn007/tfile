/// Bucket of Layer.
///
/// For T-ORAM

#[allow(dead_code)]

pub struct LayerOne {
    /// height of the layer
    height: i64,

    /// buckets of the layer,
    /// each i64 indicates a bucket number to be stored
    buckets: Vec<i64>,

    /// Space of the layer
    len: i64
}

impl LayerOne {
    pub fn new(h: i64) -> Self {
        let l = Self {
            height: h,
            buckets: std::vec::from_elem(0,  1 << h),
            len: 1 << h
        };

        l
    }

    pub fn len(&self) -> i64 {
        self.len
    }
}

pub struct Layer {
    /// layers of the Layer Structure
    layers : Vec<LayerOne>,

    /// height of Layer
    height : i64
}

impl Layer {
    pub fn new(height: i64) -> Self {
        let mut layers = Vec::new();
        let mut i = 0;
        while i <= height {
            let layer = LayerOne::new(i);
            layers.push(layer);
            i += 1;
        }
        Self {
            layers,
            height
        }
    }

    /// Return the number of layers in a Layer
    pub fn height(&self) -> i64 {
        self.height
    }

    pub fn len(&self, l: i64) -> i64 {
        self.layers[l as usize].len()
    }
}