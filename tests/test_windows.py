from analyzer.windows import busiest_window


def test_no_events_gives_none():
    assert busiest_window([], 10) is None


def test_counts_distinct_values_only():
    events = [(1.0, "a"), (2.0, "a"), (3.0, "b")]

    window = busiest_window(events, 10)

    assert window.count == 2
    assert (window.start, window.end) == (1.0, 3.0)


def test_events_further_apart_than_window_are_not_combined():
    events = [(0.0, "a"), (5.0, "b"), (100.0, "c"), (101.0, "d"), (102.0, "e")]

    window = busiest_window(events, 10)

    assert window.values == {"c", "d", "e"}


def test_value_leaves_only_when_its_last_copy_leaves():
    # "a" at t=0 drops out at t=11, but "a" at t=9 keeps it in the window.
    events = [(0.0, "a"), (9.0, "a"), (11.0, "b")]

    window = busiest_window(events, 10)

    assert window.values == {"a", "b"}


def test_unsorted_input_is_handled():
    events = [(3.0, "c"), (1.0, "a"), (2.0, "b")]

    assert busiest_window(events, 10).count == 3
