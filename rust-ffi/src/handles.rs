use std::sync::{Mutex, MutexGuard};

const SLOT_BITS: u32 = 16;
const SLOT_MASK: u32 = (1 << SLOT_BITS) - 1;
const KIND_RING: u32 = 1 << 31;
const GEN_MAX: u32 = 0x7FFF;

pub struct HandleTable<T> {
    slots: Vec<Slot<T>>,
}

struct Slot<T> {
    generation: u32,
    value: Option<T>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InsertError {
    Exhausted,
}

impl<T> HandleTable<T> {
    pub const fn new() -> Self {
        Self { slots: Vec::new() }
    }

    pub fn insert(&mut self, value: T) -> Result<u32, InsertError> {
        for (index, slot) in self.slots.iter_mut().enumerate() {
            if slot.value.is_none() && slot.generation != 0 {
                slot.value = Some(value);
                return Ok(pack(index as u32, slot.generation));
            }
        }
        if self.slots.len() > SLOT_MASK as usize {
            return Err(InsertError::Exhausted);
        }
        self.slots
            .try_reserve(1)
            .map_err(|_| InsertError::Exhausted)?;
        let generation = 1u32;
        self.slots.push(Slot {
            generation,
            value: Some(value),
        });
        Ok(pack((self.slots.len() - 1) as u32, generation))
    }

    pub fn get(&self, handle: u32) -> Result<&T, ()> {
        let slot = self.slot(handle)?;
        slot.value.as_ref().ok_or(())
    }

    pub fn release(&mut self, handle: u32) -> Result<(), ()> {
        let (slot_index, generation) = unpack(handle);
        let slot = self.slots.get_mut(slot_index as usize).ok_or(())?;
        if slot.generation != generation || slot.value.is_none() {
            return Err(());
        }
        slot.value = None;
        if slot.generation >= GEN_MAX {
            slot.generation = 0;
        } else {
            slot.generation += 1;
        }
        Ok(())
    }

    fn slot(&self, handle: u32) -> Result<&Slot<T>, ()> {
        let (slot_index, generation) = unpack(handle);
        let slot = self.slots.get(slot_index as usize).ok_or(())?;
        if slot.generation != generation {
            return Err(());
        }
        Ok(slot)
    }
}

fn pack(slot: u32, generation: u32) -> u32 {
    (generation << SLOT_BITS) | (slot & SLOT_MASK)
}

fn unpack(handle: u32) -> (u32, u32) {
    (handle & SLOT_MASK, (handle >> SLOT_BITS) & GEN_MAX)
}

fn require_srs(handle: u32) -> Result<u32, ()> {
    if handle & KIND_RING != 0 {
        return Err(());
    }
    Ok(handle)
}

fn require_ring(handle: u32) -> Result<u32, ()> {
    if handle & KIND_RING == 0 {
        return Err(());
    }
    Ok(handle & !KIND_RING)
}

static SRS: Mutex<HandleTable<Vec<u8>>> = Mutex::new(HandleTable::new());
static RINGS: Mutex<HandleTable<Vec<u8>>> = Mutex::new(HandleTable::new());

fn lock(table: &'static Mutex<HandleTable<Vec<u8>>>) -> MutexGuard<'static, HandleTable<Vec<u8>>> {
    table.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

pub fn insert_srs(bytes: Vec<u8>) -> Result<u32, InsertError> {
    lock(&SRS).insert(bytes)
}

pub fn get_srs(handle: u32) -> Result<Vec<u8>, ()> {
    let handle = require_srs(handle)?;
    lock(&SRS).get(handle).cloned()
}

pub fn release_srs(handle: u32) -> Result<(), ()> {
    let handle = require_srs(handle)?;
    lock(&SRS).release(handle)
}

pub fn insert_ring(verifier_key: Vec<u8>) -> Result<u32, InsertError> {
    Ok(lock(&RINGS).insert(verifier_key)? | KIND_RING)
}

pub fn get_ring(handle: u32) -> Result<Vec<u8>, ()> {
    let handle = require_ring(handle)?;
    lock(&RINGS).get(handle).cloned()
}

pub fn release_ring(handle: u32) -> Result<(), ()> {
    let handle = require_ring(handle)?;
    lock(&RINGS).release(handle)
}
