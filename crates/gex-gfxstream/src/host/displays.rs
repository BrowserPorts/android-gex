//! The host's displays, as gfxstream keeps them when no emulator gives it
//! its own (`host/common/display_operations.cpp`, the default
//! `gfxstream_multi_display_ops`): a table by id, empty until the guest's
//! composer creates its displays (`rcCreateDisplayById(0)` for the primary,
//! `rcCreateDisplay` for one more, numbered from 6), each with a pose, a
//! density, the color buffer it shows and a color transform. A call about a
//! display that is not there fails (-1); creating one that is there
//! succeeds and changes nothing.

use std::collections::BTreeMap;

/// The first id `rcCreateDisplay` gives (`kDeveloperDisplayIdBegin`).
const DEVELOPER_DISPLAY_ID_BEGIN: u32 = 6;
/// How many displays there may be, and the end of the ids given
/// (`kMaxDisplays`).
const MAX_DISPLAYS: u32 = 11;
/// The id that asks for one to be chosen (`FrameBuffer::s_invalidIdMultiDisplay`,
/// `kInvalidDisplayId`).
pub const INVALID_DISPLAY_ID: u32 = 0xFFFF_FFAB;

/// The identity, a display's color transform until one is set.
const IDENTITY: [f32; 16] = [1., 0., 0., 0., 0., 1., 0., 0., 0., 0., 1., 0., 0., 0., 0., 1.];

#[derive(Clone, Debug, PartialEq)]
pub struct Display {
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
    pub dpi: u32,
    pub color_buffer: u32,
    pub color_transform: [f32; 16],
}

impl Default for Display {
    fn default() -> Display {
        Display { x: 0, y: 0, width: 0, height: 0, dpi: 0, color_buffer: 0, color_transform: IDENTITY }
    }
}

#[derive(Default, Debug)]
pub struct Displays(BTreeMap<u32, Display>);

impl Displays {
    /// `create_display`: `id`, or for [`INVALID_DISPLAY_ID`] the first free
    /// id from 6; the id it has, or `None` for -1 (no room, or no id free).
    pub fn create(&mut self, id: u32) -> Option<u32> {
        if self.0.len() as u32 >= MAX_DISPLAYS {
            return None;
        }
        if self.0.contains_key(&id) {
            return Some(id);
        }
        let id = if id == INVALID_DISPLAY_ID {
            (DEVELOPER_DISPLAY_ID_BEGIN..MAX_DISPLAYS).find(|i| !self.0.contains_key(i))?
        } else {
            id
        };
        self.0.insert(id, Display::default());
        Some(id)
    }

    /// `destroy_display`: always succeeds.
    pub fn destroy(&mut self, id: u32) {
        self.0.remove(&id);
    }

    pub fn get(&self, id: u32) -> Option<&Display> {
        self.0.get(&id)
    }

    pub fn get_mut(&mut self, id: u32) -> Option<&mut Display> {
        self.0.get_mut(&id)
    }

    /// `get_color_buffer_display`: the display that shows `cb`, the lowest
    /// id first.
    pub fn showing(&self, cb: u32) -> Option<u32> {
        self.0.iter().find(|(_, d)| d.color_buffer == cb).map(|(&id, _)| id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn displays_are_made_numbered_and_kept_as_gfxstreams_default() {
        let mut d = Displays::default();
        // Nothing until the composer creates the primary display.
        assert_eq!(d.get(0), None);
        assert_eq!(d.create(0), Some(0));
        assert_eq!(d.create(0), Some(0), "again: there already, success");
        assert_eq!(d.get(0), Some(&Display::default()));
        // One more is numbered from 6, the first free.
        assert_eq!(d.create(INVALID_DISPLAY_ID), Some(6));
        assert_eq!(d.create(INVALID_DISPLAY_ID), Some(7));
        d.destroy(6);
        assert_eq!(d.create(INVALID_DISPLAY_ID), Some(6));
        d.destroy(42);
        // At most 11, and none past id 10 given.
        for i in 8..11 {
            assert_eq!(d.create(INVALID_DISPLAY_ID), Some(i));
        }
        assert_eq!(d.create(INVALID_DISPLAY_ID), None, "ids 6 to 10 are taken");
        for i in 1..6 {
            assert_eq!(d.create(i), Some(i));
        }
        assert_eq!(d.0.len(), 11);
        assert_eq!(d.create(20), None, "no more than 11");
        // A color buffer's display, the lowest id first.
        d.get_mut(7).unwrap().color_buffer = 5;
        d.get_mut(3).unwrap().color_buffer = 5;
        assert_eq!(d.showing(5), Some(3));
        assert_eq!(d.showing(9), None);
    }
}
