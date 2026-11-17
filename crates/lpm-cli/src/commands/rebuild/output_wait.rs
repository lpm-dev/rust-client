//! Waiting for the output of a process that may end while it is read.

use std::sync::atomic::{AtomicBool, Ordering};

pub(in crate::commands) enum Looked {
    /// Output, or the stream's end, is there to read.
    Readable,
    Nothing,
    /// Nothing more will come.
    Closed,
    /// The look was cut short and found out nothing.
    #[cfg(any(unix, test))]
    Interrupted,
}

/// Waits until a stream is readable, and says whether it is. `look` checks
/// the stream once; given `true` it may wait a short while for output.
///
/// A process can write its output and end right after a look found nothing.
/// So only a look that began after the process was seen to have ended shows
/// that it left nothing to read.
pub(in crate::commands) fn wait_for_output<E>(
    process_finished: &AtomicBool,
    mut look: impl FnMut(bool) -> Result<Looked, E>,
) -> Result<bool, E> {
    loop {
        let finished = process_finished.load(Ordering::Acquire);
        match look(!finished)? {
            Looked::Readable => return Ok(true),
            Looked::Closed => return Ok(false),
            Looked::Nothing if finished => return Ok(false),
            Looked::Nothing => {}
            #[cfg(any(unix, test))]
            Looked::Interrupted => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Looked, wait_for_output};
    use std::convert::Infallible;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[test]
    fn output_written_as_the_process_ends_is_still_waited_for() {
        let finished = AtomicBool::new(false);
        let mut waits = Vec::new();

        let readable = wait_for_output(&finished, |may_wait| {
            waits.push(may_wait);
            if waits.len() > 1 {
                return Ok::<_, Infallible>(Looked::Readable);
            }
            finished.store(true, Ordering::Release);
            Ok(Looked::Nothing)
        });

        assert_eq!(readable, Ok(true));
        assert_eq!(waits, [true, false]);
    }

    #[test]
    fn a_process_that_ended_without_output_is_looked_at_once_without_waiting() {
        let finished = AtomicBool::new(true);
        let mut waits = Vec::new();

        let readable = wait_for_output(&finished, |may_wait| {
            waits.push(may_wait);
            Ok::<_, Infallible>(Looked::Nothing)
        });

        assert_eq!(readable, Ok(false));
        assert_eq!(waits, [false]);
    }

    #[test]
    fn an_interrupted_look_is_made_again_without_waiting_once_the_process_ended() {
        let finished = AtomicBool::new(false);
        let mut waits = Vec::new();

        let readable = wait_for_output(&finished, |may_wait| {
            waits.push(may_wait);
            if waits.len() < 3 {
                finished.store(true, Ordering::Release);
                return Ok::<_, Infallible>(Looked::Interrupted);
            }
            Ok(Looked::Nothing)
        });

        assert_eq!(readable, Ok(false));
        assert_eq!(waits, [true, false, false]);
    }

    #[test]
    fn a_stream_that_closed_ends_the_wait_while_the_process_runs() {
        let finished = AtomicBool::new(false);

        let readable = wait_for_output(&finished, |_may_wait| Ok::<_, Infallible>(Looked::Closed));

        assert_eq!(readable, Ok(false));
    }
}
