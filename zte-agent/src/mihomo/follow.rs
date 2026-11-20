//! Decisions made before changing a running core and after auditing its state.
use super::routing::{Mode, Selected};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Before {
    Keep,
    Hold,
    ExcludeProviders,
}

pub(super) fn plan(may_return: bool, refreshing: &[String]) -> Before {
    if !may_return {
        Before::Keep
    } else if refreshing.is_empty() {
        Before::Hold
    } else {
        Before::ExcludeProviders
    }
}

pub(super) fn decide(
    files_changed: bool,
    expected: (Mode, &Selected),
    observed: Option<(Mode, &Selected)>,
) -> bool {
    files_changed || observed != Some(expected)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_confirmed_choices_and_unchanged_files_can_keep_the_plan() {
        let selected = Selected::new();
        let same = (Mode::Rule, &selected);
        assert!(!decide(false, same, Some(same)));
        assert!(decide(false, same, None));
        assert!(decide(true, same, Some(same)));
        assert!(decide(false, same, Some((Mode::Global, &selected))));
        assert_eq!(plan(false, &[]), Before::Keep);
        assert_eq!(plan(true, &[]), Before::Hold);
        assert_eq!(plan(true, &["Ads".into()]), Before::ExcludeProviders);
    }
}
