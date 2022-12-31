use std::sync::Mutex;

pub struct AppStateWithCounter {
    pub counter: Mutex<usize>,
}
